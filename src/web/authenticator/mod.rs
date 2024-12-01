use axum::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use super::{errors::token_error::TokenError, extractors::token::Token};
pub(crate) mod symmetric;
pub(crate) mod asymmetric;

#[async_trait]
pub trait Authenticator<T: Serialize + DeserializeOwned>: Send + Sync {
    async fn verify_jwt(
        &self,
        token: &str,
        aud: &[String]
    ) -> Result<Token<T>, TokenError>;
    async fn create_jwt(
        &self,
        claims: T,
    ) -> Result<String, TokenError>;
}