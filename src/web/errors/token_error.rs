use thiserror::Error;

use super::http_error::HttpError;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("jsonwebtoken crate: {0}")]
    CrateError(String),
    #[error("invalid_key")]
    InvalidKeyError,
    #[error("expired_token")]
    ExpiredTokenError,
}

impl From<TokenError> for HttpError {
    fn from(value: TokenError) -> Self {
        match value {
            TokenError::CrateError(e) => HttpError::Simple(
                axum::http::StatusCode::BAD_REQUEST, 
                format!("bad_token: {}", e.to_string())
            ),
            TokenError::InvalidKeyError => HttpError::Simple(
                axum::http::StatusCode::BAD_REQUEST, 
                "invalid_key".to_string()
            ),
            TokenError::ExpiredTokenError => HttpError::Simple(
                axum::http::StatusCode::UNAUTHORIZED, 
                "expired_token".to_string(),
            ),
        }
    }
}