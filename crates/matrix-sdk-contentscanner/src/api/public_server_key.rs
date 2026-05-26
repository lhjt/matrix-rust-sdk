use matrix_sdk::RumaApiError;
use ruma::{
    api::{
        IncomingResponse, Metadata, OutgoingRequest,
        auth_scheme::{AuthScheme, NoAuthentication},
        error::{FromHttpResponseError, IntoHttpError},
        path_builder::PathBuilder,
    },
    exports::{
        bytes::BufMut,
        http::{Request, Response},
        serde_json,
    },
    metadata,
};
use serde::Deserialize;

metadata! {
    @for PublicServerKeyRequest,
    method: GET,
    rate_limited: false,
    authentication: NoAuthentication,
    history: {
        unstable => "/_matrix/media_proxy/unstable/public_key",
    },
}

/// The HTTP request body for fetching the public server key.
#[derive(Debug, Clone)]
pub(crate) struct PublicServerKeyRequest {
    scanner_url: String,
}

impl PublicServerKeyRequest {
    pub(crate) fn new(scanner_url: impl Into<String>) -> Self {
        Self { scanner_url: scanner_url.into() }
    }
}

impl OutgoingRequest for PublicServerKeyRequest {
    type EndpointError = RumaApiError;
    type IncomingResponse = PublicServerKeyResponse;

    fn try_into_http_request<T: Default + BufMut + AsRef<[u8]>>(
        self,
        _base_url: &str,
        _authentication_input: <Self::Authentication as AuthScheme>::Input<'_>,
        path_builder_input: <Self::PathBuilder as PathBuilder>::Input<'_>,
    ) -> Result<Request<T>, IntoHttpError> {
        let url = Self::make_endpoint_url(path_builder_input, &self.scanner_url, &[], "")?;
        Ok(Request::builder().method(Self::METHOD).uri(url).body(T::default())?)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PublicServerKeyResponse {
    pub(crate) public_key: String,
}

impl IncomingResponse for PublicServerKeyResponse {
    type EndpointError = RumaApiError;

    fn try_from_http_response<T: AsRef<[u8]>>(
        response: Response<T>,
    ) -> Result<Self, FromHttpResponseError<Self::EndpointError>> {
        Ok(serde_json::from_slice::<PublicServerKeyResponse>(response.body().as_ref())?)
    }
}
