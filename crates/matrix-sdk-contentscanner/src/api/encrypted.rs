use matrix_sdk::{RumaApiError, encryption::vodozemac::pk_encryption::PkEncryption};
use matrix_sdk_crypto::olm::Curve25519PublicKey;
use ruma::{
    api::{
        Metadata, OutgoingRequest,
        auth_scheme::{AccessTokenOptional, AuthScheme, SendAccessToken},
        error::IntoHttpError,
        path_builder::PathBuilder,
    },
    events::room::EncryptedFile,
    exports::{bytes::BufMut, http::Request, serde_json},
    metadata,
};

use crate::{EncryptedFileRequest, api::DownloadAndScanMediaResponse};

metadata! {
    @for DownloadAndScanEncryptedMediaRequest,
    method: POST,
    rate_limited: false,
    authentication: AccessTokenOptional,
    history: {
        unstable => "/_matrix/media_proxy/unstable/download_encrypted",
    },
}

/// The HTTP request body for downloading and scanning encrypted media.
#[derive(Debug, Clone)]
pub(crate) struct DownloadAndScanEncryptedMediaRequest {
    scanner_url: String,
    public_key: Option<Curve25519PublicKey>,
    encrypted_file: EncryptedFile,
}

impl DownloadAndScanEncryptedMediaRequest {
    pub(crate) fn new(
        scanner_url: impl Into<String>,
        public_key: Option<Curve25519PublicKey>,
        encrypted_file: EncryptedFile,
    ) -> Self {
        Self { scanner_url: scanner_url.into(), public_key, encrypted_file }
    }
}

impl OutgoingRequest for DownloadAndScanEncryptedMediaRequest {
    type EndpointError = RumaApiError;
    type IncomingResponse = DownloadAndScanMediaResponse;

    fn try_into_http_request<T: Default + BufMut + AsRef<[u8]>>(
        self,
        _base_url: &str,
        authentication_input: <Self::Authentication as AuthScheme>::Input<'_>,
        path_builder_input: <Self::PathBuilder as PathBuilder>::Input<'_>,
    ) -> Result<Request<T>, IntoHttpError> {
        let url = Self::make_endpoint_url(path_builder_input, &self.scanner_url, &[], "")?;

        let body = if let Some(public_key) = &self.public_key {
            // Generate an encrypted request body.
            let encryption =
                PkEncryption::from_key(Curve25519PublicKey::from_bytes(*public_key.as_bytes()));

            let body_to_encrypt = EncryptedFileRequest::from_file_info(self.encrypted_file.clone());
            let json_body_to_encrypt = serde_json::to_string(&body_to_encrypt)?;
            let pk_message = encryption
                .encrypt(json_body_to_encrypt.as_bytes())
                .map_err(|e| IntoHttpError::Authentication(e.into()))?;
            EncryptedFileRequest::from_encrypted_body(pk_message.into())
        } else {
            EncryptedFileRequest::from_file_info(self.encrypted_file)
        };

        let body = ruma::serde::json_to_buf(&body)?;

        let mut request = Request::builder().method(Self::METHOD).uri(url).body(body)?;
        if let Some(access_token) = authentication_input.get_required_for_endpoint() {
            Self::Authentication::add_authentication(
                &mut request,
                SendAccessToken::IfRequired(access_token),
            )?
        }

        Ok(request)
    }
}
