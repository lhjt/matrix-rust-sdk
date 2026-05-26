use matrix_sdk::RumaApiError;
use ruma::{
    api::{EndpointError, IncomingResponse, error::FromHttpResponseError},
    exports::http::Response,
};
use serde::Deserialize;

pub mod encrypted;
pub mod public_server_key;
pub mod unencrypted;

/// The HTTP response content for a successful request to download and scan
/// media.
#[derive(Debug, Deserialize)]
pub struct DownloadAndScanMediaResponse {
    /// The content that was previously uploaded.
    pub content: Vec<u8>,
}

impl IncomingResponse for DownloadAndScanMediaResponse {
    type EndpointError = RumaApiError;

    fn try_from_http_response<T: AsRef<[u8]>>(
        response: Response<T>,
    ) -> Result<Self, FromHttpResponseError<Self::EndpointError>> {
        if response.status().is_success() {
            Ok(Self { content: response.body().as_ref().to_vec() })
        } else {
            Err(FromHttpResponseError::Server(Self::EndpointError::from_http_response(response)))
        }
    }
}
