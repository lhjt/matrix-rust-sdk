use matrix_sdk::RumaApiError;
use ruma::{
    api::{EndpointError, IncomingResponse, error::FromHttpResponseError},
    exports::{http::Response, serde_json},
};
use serde::Deserialize;

pub mod encrypted;
pub mod unencrypted;

#[derive(Debug, Deserialize)]
pub struct MediaScanResponse {
    pub clean: bool,
    pub info: String,
}

impl IncomingResponse for MediaScanResponse {
    type EndpointError = RumaApiError;

    fn try_from_http_response<T: AsRef<[u8]>>(
        response: Response<T>,
    ) -> Result<Self, FromHttpResponseError<Self::EndpointError>> {
        if response.status().is_success() {
            let content = response.body().as_ref().to_vec();
            let media_scan_response: MediaScanResponse = serde_json::from_slice(&content)?;
            Ok(media_scan_response)
        } else {
            Err(FromHttpResponseError::Server(Self::EndpointError::from_http_response(response)))
        }
    }
}
