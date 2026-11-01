//! Request helpers shared by the L7c routes.

use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use rand::RngCore;
use uuid::Uuid;

use crate::error::ApiError;

/// JSON body whose rejections (syntax, unknown field, wrong type, wrong content type) are
/// `400 problem+json` like every other API error.
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|axum::Json(v)| Self(v))
            .map_err(|e| ApiError::BadRequest(e.body_text()))
    }
}

/// Session given by the `X-Afw-Session` header, if any.
pub fn session_header(headers: &HeaderMap) -> Result<Option<Uuid>, ApiError> {
    match headers.get("x-afw-session") {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .map(Some)
            .ok_or_else(|| ApiError::BadRequest("invalid X-Afw-Session header".into())),
    }
}

/// Random secret `<prefix><43 base64url chars>` (256 bits from the OS CSPRNG).
pub fn new_secret(prefix: &str) -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}
