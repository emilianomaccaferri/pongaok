use std::env;

use axum::async_trait;

use crate::web::{errors::token_error::TokenError, extractors::token::{PongaToken, Token}};

use super::Authenticator;

pub struct Symmetric {
    pub secret: String,
}
#[async_trait]
impl Authenticator<PongaToken> for Symmetric {
    async fn verify_jwt(
        &self,
        token: &str,
        aud: &[String]
    ) -> Result<Token<PongaToken>, TokenError> {
        let token: Result<Token<PongaToken>, TokenError> = Token::from_string(token, &self.secret, aud).await.into();
        Ok(token?)
    }

    async fn create_jwt(
        &self,
        claims: PongaToken,
    ) -> Result<String, TokenError> {
        let str_token = Token::sign(&claims, &self.secret).await?;
        Ok(str_token)
    }
}

impl Symmetric {
    pub fn new() -> Self {
        Symmetric {
            secret: env::var("JWT_SECRET").expect("JWT_SECRET is not defined"),
        }
    }
}