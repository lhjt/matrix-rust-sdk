use std::sync::Arc;

use api::{
    encrypted::DownloadAndScanEncryptedMediaRequest, public_server_key::PublicServerKeyRequest,
    unencrypted::DownloadAndScanMediaRequest,
};
use matrix_sdk::{
    Error, IdParseError, WeakClient, async_trait,
    encryption::vodozemac::pk_encryption::Message,
    locks::Mutex,
    media::{MediaFetcher, MediaFetcherBuilder, MediaFetcherError, MediaRequestParameters},
    ruma::events::room::MediaSource,
};
use matrix_sdk_crypto::olm::Curve25519PublicKey;
use ruma::{
    events::room::EncryptedFile,
    serde::{Base64, base64::Standard},
};
use serde::Serialize;
use tracing::trace;

use crate::api::DownloadAndScanMediaResponse;

mod api;

#[derive(Debug)]
pub struct ContentScanner {
    scanner_url: String,
    weak_client: WeakClient,
    public_server_key: Arc<Mutex<Option<String>>>,
}

impl ContentScanner {
    pub fn new(scanner_url: impl Into<String>, weak_client: WeakClient) -> Self {
        Self {
            scanner_url: scanner_url.into(),
            weak_client,
            public_server_key: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) async fn fetch_public_server_key(&self) -> Result<String, Error> {
        let Some(client) = self.weak_client.get() else {
            return Err(Error::MediaFetcher(MediaFetcherError::MissingClient));
        };

        let response = client.send(PublicServerKeyRequest::new(self.scanner_url.clone())).await?;
        Ok(response.public_key)
    }

    pub(crate) async fn get_media(
        &self,
        media_source: &MediaSource,
    ) -> Result<DownloadAndScanMediaResponse, Error> {
        let Some(client) = self.weak_client.get() else {
            return Err(Error::MediaFetcher(MediaFetcherError::MissingClient));
        };
        match &media_source {
            MediaSource::Encrypted(encrypted) => {
                // Get the public server key if we don't have it yet.
                let public_server_key = {
                    let ret =
                        if let Some(public_server_key) = (*self.public_server_key.lock()).clone() {
                            trace!("Using cached public server key");
                            Some(public_server_key)
                        } else {
                            trace!("Using cached public server key");
                            self.fetch_public_server_key().await.ok()
                        };

                    if let Some(public_server_key) = &ret {
                        trace!("Saved new public server key");
                        let mut guard = self.public_server_key.lock();
                        let _ = guard.insert(public_server_key.clone());
                    }

                    ret
                };

                let public_server_key =
                    public_server_key.and_then(|key| Curve25519PublicKey::from_base64(&key).ok());

                Ok(client
                    .send(DownloadAndScanEncryptedMediaRequest::new(
                        self.scanner_url.clone(),
                        public_server_key,
                        *encrypted.clone(),
                    ))
                    .await?)
            }
            MediaSource::Plain(mxc) => {
                let (server_name, media_id) =
                    mxc.parts().map_err(|e| Error::Identifier(IdParseError::InvalidMxcUri(e)))?;
                Ok(client
                    .send(DownloadAndScanMediaRequest::new(
                        &self.scanner_url,
                        server_name.as_str(),
                        media_id,
                    ))
                    .await?)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EncryptedBody {
    ciphertext: String,
    mac: String,
    ephemeral: String,
}

impl From<Message> for EncryptedBody {
    fn from(value: Message) -> Self {
        Self {
            ciphertext: Base64::<Standard>::new(value.ciphertext).to_string(),
            mac: Base64::<Standard>::new(value.mac).to_string(),
            ephemeral: value.ephemeral_key.to_base64(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EncryptedFileRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<EncryptedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_body: Option<EncryptedBody>,
}

impl EncryptedFileRequest {
    pub(crate) fn from_file_info(file_info: EncryptedFile) -> Self {
        Self { file: Some(file_info), encrypted_body: None }
    }

    pub(crate) fn from_encrypted_body(encrypted_body: EncryptedBody) -> Self {
        Self { file: None, encrypted_body: Some(encrypted_body) }
    }
}

pub struct ContentScannerMediaFetcher {
    pub content_scanner: ContentScanner,
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl MediaFetcher for ContentScannerMediaFetcher {
    async fn fetch_media_content(
        &self,
        request: &MediaRequestParameters,
    ) -> matrix_sdk::Result<Vec<u8>, Error> {
        Ok(self.content_scanner.get_media(&request.source).await?.content)
    }
}

pub struct ContentScannerMediaFetcherBuilder {
    scanner_url: String,
}

impl ContentScannerMediaFetcherBuilder {
    pub fn new(scanner_url: impl Into<String>) -> Self {
        Self { scanner_url: scanner_url.into() }
    }
}

impl MediaFetcherBuilder for ContentScannerMediaFetcherBuilder {
    fn build(&self, weak_client: WeakClient) -> Arc<dyn MediaFetcher> {
        let content_scanner = ContentScanner::new(&self.scanner_url, weak_client);
        Arc::new(ContentScannerMediaFetcher { content_scanner })
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk::{WeakClient, test_utils::mocks::MatrixMockServer};
    use matrix_sdk_test::async_test;
    use ruma::{
        api::MatrixVersion,
        events::room::{
            EncryptedFile, EncryptedFileHash, EncryptedFileHashes, EncryptedFileInfo, MediaSource,
            V2EncryptedFileInfo,
        },
        exports::{http::StatusCode, serde_json::json},
        owned_mxc_uri,
        serde::Base64,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header_exists, method, path, path_regex},
    };

    use crate::ContentScanner;

    #[async_test]
    async fn test_fetch_public_key() {
        let server = MatrixMockServer::new().await;
        let client =
            server.client_builder().server_versions(vec![MatrixVersion::V1_11]).build().await;

        let content_scanner =
            ContentScanner::new("http://localhost:8080", WeakClient::from_client(&client));
        content_scanner.fetch_public_server_key().await.expect("Load public key");
    }

    #[async_test]
    async fn test_get_media() {
        let server = MatrixMockServer::new().await;
        let client =
            server.client_builder().server_versions(vec![MatrixVersion::V1_11]).build().await;

        let content_scanner_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/_matrix/media_proxy/unstable/download/.+/.+"))
            .and(header_exists("Authorization"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
            )
            .mount(&content_scanner_server)
            .await;

        let content_scanner =
            ContentScanner::new(content_scanner_server.uri(), WeakClient::from_client(&client));
        let media_source =
            MediaSource::Plain(owned_mxc_uri!("mxc://matrix.org/RhfpOXOzAwzkuqcmbgMwQUrJ"));
        content_scanner.get_media(&media_source).await.expect("Get media");
    }

    #[async_test]
    async fn test_get_media_unsupported() {
        let server = MatrixMockServer::new().await;
        let client =
            server.client_builder().server_versions(vec![MatrixVersion::V1_11]).build().await;

        let content_scanner_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/_matrix/media_proxy/unstable/download/.+/.+"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "reason": "MCS_MIME_TYPE_FORBIDDEN",
                "info": "File type: application/octet-stream not allowed",
            })))
            .mount(&content_scanner_server)
            .await;

        let content_scanner =
            ContentScanner::new(content_scanner_server.uri(), WeakClient::from_client(&client));
        let media_source =
            MediaSource::Plain(owned_mxc_uri!("mxc://matrix.org/ckTaStcNnFXLzKApkBmgRDoC"));
        let err = content_scanner.get_media(&media_source).await.expect_err("Get media error");
        let client_error = err.as_client_api_error().expect("Get client error");
        assert_eq!(client_error.status_code, StatusCode::FORBIDDEN);
        assert_eq!(
            client_error.to_string(),
            "[403] {\"info\":\"File type: application/octet-stream not allowed\",\"reason\":\"MCS_MIME_TYPE_FORBIDDEN\"}"
        );
    }

    #[async_test]
    async fn test_get_encrypted_media() {
        let server = MatrixMockServer::new().await;
        let client =
            server.client_builder().server_versions(vec![MatrixVersion::V1_11]).build().await;

        let content_scanner_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/_matrix/media_proxy/unstable/download_encrypted"))
            .and(header_exists("Authorization"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
            )
            .mount(&content_scanner_server)
            .await;

        let content_scanner =
            ContentScanner::new(content_scanner_server.uri(), WeakClient::from_client(&client));
        let file_info = EncryptedFileInfo::V2(V2EncryptedFileInfo::new(
            Base64::parse("9lpOscZyMOZRCF3v867nPPo3WPNMZt9JXMsuYiWRszc".as_bytes()).expect("k"),
            Base64::parse("czvdfKSjfLEAAAAAAAAAAA".as_bytes()).expect("iv"),
        ));
        let mut hashes = EncryptedFileHashes::new();
        hashes.insert(EncryptedFileHash::Sha256(
            Base64::parse("SBbJ3hINT2LgwXK8ev82enjnhubUy5UuKGDF3SezAhs".as_bytes()).expect("hash"),
        ));
        let media_source = MediaSource::Encrypted(Box::new(EncryptedFile::new(
            owned_mxc_uri!(
                "mxc://element.io/b50f38aa8ae820c75992370e4e944a045481e3932057062074730676224"
            ),
            file_info,
            hashes,
        )));
        content_scanner.get_media(&media_source).await.expect("Get media");
    }

    #[async_test]
    async fn test_get_encrypted_media_unsupported() {
        let server = MatrixMockServer::new().await;
        let client =
            server.client_builder().server_versions(vec![MatrixVersion::V1_11]).build().await;

        let content_scanner_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/_matrix/media_proxy/unstable/download_encrypted"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "reason": "MCS_MIME_TYPE_FORBIDDEN",
                "info": "File type: application/octet-stream not allowed",
            })))
            .mount(&content_scanner_server)
            .await;

        let content_scanner =
            ContentScanner::new(content_scanner_server.uri(), WeakClient::from_client(&client));
        let file_info = EncryptedFileInfo::V2(V2EncryptedFileInfo::new(
            Base64::parse("tdHdCI5mc-g29IYfhYx2wkA5o-bILP9-nXY6Np1uSnM".as_bytes()).expect("k"),
            Base64::parse("IBFdH65KqhoAAAAAAAAAAA".as_bytes()).expect("iv"),
        ));
        let mut hashes = EncryptedFileHashes::new();
        hashes.insert(EncryptedFileHash::Sha256(
            Base64::parse("HSkkamvMSvF3Q30HInorh0ccPrxjgu+wp1vyUOmov/8".as_bytes()).expect("hash"),
        ));
        let media_source = MediaSource::Encrypted(Box::new(EncryptedFile::new(
            owned_mxc_uri!("mxc://matrix.org/WlfuejQQdpvWiWVpAGwfIKJL"),
            file_info,
            hashes,
        )));
        let err = content_scanner.get_media(&media_source).await.expect_err("Invalid type error");
        let client_error = err.as_client_api_error().expect("Invalid error");
        assert_eq!(client_error.status_code, StatusCode::FORBIDDEN);
        assert_eq!(
            client_error.to_string(),
            "[403] {\"info\":\"File type: application/octet-stream not allowed\",\"reason\":\"MCS_MIME_TYPE_FORBIDDEN\"}"
        );
    }
}
