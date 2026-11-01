//! API errors rendered as RFC 7807 `application/problem+json` ([`afw_core::api::Problem`]).

use afw_core::api::Problem;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {message}")]
    Conflict { message: String },
    /// Resource locked by another session (HTTP 423).
    #[error("locked by {by}")]
    Locked { by: String },
    /// Internal error; the message is logged, never returned to the client.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Locked { .. } => StatusCode::LOCKED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn problem(&self) -> Problem {
        let status = self.status();
        let detail = match self {
            Self::BadRequest(m) | Self::Forbidden(m) => Some(m.clone()),
            Self::Conflict { message } => Some(message.clone()),
            Self::Locked { by } => Some(format!("locked by {by}")),
            Self::Unauthorized | Self::NotFound | Self::Internal(_) => None,
        };
        Problem {
            kind: "about:blank".to_owned(),
            title: status.canonical_reason().unwrap_or("Error").to_owned(),
            status: status.as_u16(),
            detail,
            instance: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(message) = &self {
            tracing::error!(%message, "internal API error");
        }
        let status = self.status();
        let body = serde_json::to_vec(&self.problem()).unwrap_or_default();
        let mut res = (status, body).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        if status == StatusCode::UNAUTHORIZED {
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        res
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => Self::NotFound,
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(format!("{e:#}"))
    }
}
