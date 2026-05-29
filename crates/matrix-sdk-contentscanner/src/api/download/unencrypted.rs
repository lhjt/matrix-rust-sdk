use matrix_sdk::RumaApiError;
use ruma::{
    api::{
        Metadata, OutgoingRequest,
        auth_scheme::{AccessTokenOptional, AuthScheme, SendAccessToken},
        error::IntoHttpError,
        path_builder::PathBuilder,
    },
    exports::{bytes::BufMut, http::Request},
    metadata,
};

use crate::api::DownloadAndScanMediaResponse;

metadata! {
    @for DownloadAndScanMediaRequest,
    method: GET,
    rate_limited: false,
    authentication: AccessTokenOptional,
    history: {
        unstable => "/_matrix/media_proxy/unstable/download/{server_name}/{media_id}",
    },
}

/// The HTTP request body for downloading and scanning unencrypted media.
#[derive(Debug, Clone)]
pub(crate) struct DownloadAndScanMediaRequest {
    scanner_url: String,
    server_name: String,
    media_id: String,
}

impl DownloadAndScanMediaRequest {
    pub(crate) fn new(
        scanner_url: impl Into<String>,
        server_name: impl Into<String>,
        media_id: impl Into<String>,
    ) -> Self {
        Self {
            scanner_url: scanner_url.into(),
            server_name: server_name.into(),
            media_id: media_id.into(),
        }
    }
}

impl OutgoingRequest for DownloadAndScanMediaRequest {
    type EndpointError = RumaApiError;
    type IncomingResponse = DownloadAndScanMediaResponse;

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
