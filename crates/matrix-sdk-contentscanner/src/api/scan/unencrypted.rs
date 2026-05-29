use matrix_sdk::{RumaApiError, bytes::BufMut};
use ruma::{
    api::{
        Metadata, OutgoingRequest,
        auth_scheme::{AccessTokenOptional, AuthScheme, SendAccessToken},
        error::IntoHttpError,
        path_builder::PathBuilder,
    },
    exports::http::Request,
    metadata,
};

use crate::api::scan::MediaScanResponse;

metadata! {
    @for MediaScanRequest,
    method: GET,
    rate_limited: false,
    authentication: AccessTokenOptional,
    history: {
        unstable => "/_matrix/media_proxy/unstable/scan/{server_name}/{media_id}",
    },
}

/// A request to scan an unencrypted media file using the content scanner.
#[derive(Debug, Clone)]
pub struct MediaScanRequest {
    scanner_url: String,
    server_name: String,
    media_id: String,
}

impl MediaScanRequest {
    pub fn new(scanner_url: String, server_name: String, media_id: String) -> Self {
        Self { scanner_url, server_name, media_id }
    }
}

impl OutgoingRequest for MediaScanRequest {
    type EndpointError = RumaApiError;
    type IncomingResponse = MediaScanResponse;

    fn try_into_http_request<T: Default + BufMut + AsRef<[u8]>>(
        self,
        _base_url: &str,
        authentication_input: <Self::Authentication as AuthScheme>::Input<'_>,
        path_builder_input: <Self::PathBuilder as PathBuilder>::Input<'_>,
    ) -> Result<Request<T>, IntoHttpError> {
        let url = Self::make_endpoint_url(
            path_builder_input,
            &self.scanner_url,
            &[&self.server_name, &self.media_id],
            "",
        )?;

        let mut request = Request::builder().method(Self::METHOD).uri(url).body(T::default())?;

        if let Some(access_token) = authentication_input.get_required_for_endpoint() {
            Self::Authentication::add_authentication(
                &mut request,
                SendAccessToken::IfRequired(access_token),
            )?
        }

        Ok(request)
    }
}
