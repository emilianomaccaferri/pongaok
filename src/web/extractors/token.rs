use axum::{async_trait, extract::{FromRef, FromRequestParts}, http::request::Parts};
use axum_extra::headers::{Cookie, HeaderMapExt};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::web::{app_state::AppState, errors::{http_error::HttpError, token_error::TokenError}};

pub struct Token<T: Serialize + DeserializeOwned>(pub T);

impl<T> Token<T> 
    where T: Serialize + DeserializeOwned,
{
    pub async fn sign_rsa(
        token: &T,
        key: &Vec<u8>,
    ) -> Result<String, TokenError> 
    where T: Serialize, 
    {
        Ok(encode(
            &Header::new(Algorithm::RS256), 
            token,
            &EncodingKey::from_rsa_pem(&key)?,
        )?)
    }

    pub async fn sign(
        token: &T,
        key: &str,
    ) -> Result<String, TokenError> 
    {
        Ok(encode(
            &Header::new(Algorithm::HS512), 
            token,
            &EncodingKey::from_secret(key.as_ref()),
        )?)
    }

    pub async fn from_string(
        token: &str,
        key: &str,
        audience: &[String]
    ) -> Result<Token<T>, TokenError> {
        let mut alg = Validation::new(Algorithm::HS512);
        alg.set_audience(audience);
        let key = DecodingKey::from_secret(key.as_ref());
        let decoded_token = jsonwebtoken::decode::<T>(
            &token, 
            &key, 
            &alg,
        );
        match decoded_token {
            Ok(token) => Ok(Token(token.claims)),
            Err(e) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(TokenError::ExpiredTokenError),
                _ => Err(TokenError::CrateError(e.to_string())),
            },
        }
        
    }

    pub async fn from_string_jwk(
        token: &str,
        n: &str,
        e: &str,
        audience: &[String]
    ) -> Result<Token<T>, TokenError> {
        let mut alg = Validation::new(Algorithm::RS256);
        alg.set_audience(audience);
        let key = DecodingKey::from_rsa_components(n, e);
        if let Ok(k) = key {
            let decoded_token = jsonwebtoken::decode::<T>(
                &token, 
                &k, 
                &alg,
            );
            match decoded_token {
                Ok(token) => Ok(Token(token.claims)),
                Err(e) => match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(TokenError::ExpiredTokenError),
                    _ => Err(TokenError::CrateError(e.to_string())),
                },
            }
        }else{
            Err(TokenError::InvalidKeyError)
        }
        
    }
}

impl From<jsonwebtoken::errors::Error> for TokenError{
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        TokenError::CrateError(err.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PongaToken {
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub sub: String, // user id
}

/// the actual axum extractor
#[async_trait]
impl<S> FromRequestParts<S> for Token<PongaToken> 
    where 
        AppState: FromRef<S>,
        S: Send + Sync
{
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        s: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(s);
        if let Some(auth_header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(str_header) = auth_header
                .to_str() {
                    let pieces: Vec<&str> = str_header.split("Bearer ").collect();
                    if pieces.len() < 2 {
                        return Err(HttpError::Simple(
                            axum::http::StatusCode::BAD_REQUEST, 
                            "no_bearer_specified".to_string())
                        )
                    }
                    let str_token = pieces[1];
                    return Ok(
                        state.authenticator.verify_jwt(str_token, &["ponga".to_string()]).await?
                    );
                } else {
                    return Err(HttpError::Simple(
                        axum::http::StatusCode::BAD_REQUEST, 
                        "invalid_auth_header".to_string())
                    );
                }
        }
        Err(HttpError::Simple(
            axum::http::StatusCode::BAD_REQUEST, 
            "no_auth".to_string())
        )
    }
}