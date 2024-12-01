use std::{env, fs, time::Duration};

use axum::async_trait;
use serde::{Deserialize, Serialize};

use crate::web::{app_state::AppStateInitializationError, errors::token_error::TokenError, extractors::token::{PongaToken, Token}};

use super::Authenticator;

#[derive(Clone)]
pub struct Asymmetric {
    pub jwk_uri: String,
    pub n: String,
    pub e: String,
    pub private_key: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
pub struct JwksEndpointResponse {
    keys: Vec<JwkObject>,
}

#[derive(Serialize, Deserialize)]
pub struct JwkObject {
    /*{
        "kid": "tRhMfFK7AmsBcIHKMWNSsx_4cEQdNMVJwOYNkZoY8Vw",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": "tASfyjV1DoNuMhrJgOcwWHETiobD1bUvyIVisyLIxrNP8_drgirUAYjoS8XsmxoH68Y_5_70FQWZt64l9fZMKn_4PwAO7Ydhz9UVmlkkY0PKzhCZ29BOC_qHcK9im5EZdfa4CR8p0vi9jv1jWDjcp78jemDKbJUtSa1xpYH7VE40O1BSvjn6n9I6Whe-vUpAF5q8pjK0eg7PzD4cJGihrX2JZ8mL3shp6lOFxcLlk1Q7DGuPMX6GOI9_ViMWB8AyhBvBriIHRUeC097hYWnTMy8LNV_PssSDWZChminnPIFSOKi3DxzmDTozZCZFaBXyr3AbmKk2-JwdAYis_pyzlw",
        "e": "AQAB",
        "x5c": [
            "MIICmzCCAYMCBgGSdmoEQDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQxMDEwMTIzMDEyWhcNMzQxMDEwMTIzMTUyWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0BJ/KNXUOg24yGsmA5zBYcROKhsPVtS/IhWKzIsjGs0/z92uCKtQBiOhLxeybGgfrxj/n/vQVBZm3riX19kwqf/g/AA7th2HP1RWaWSRjQ8rOEJnb0E4L+odwr2KbkRl19rgJHynS+L2O/WNYONynvyN6YMpslS1JrXGlgftUTjQ7UFK+Ofqf0jpaF769SkAXmrymMrR6Ds/MPhwkaKGtfYlnyYveyGnqU4XFwuWTVDsMa48xfoY4j39WIxYHwDKEG8GuIgdFR4LT3uFhadMzLws1X8+yxINZkKGaKec8gVI4qLcPHOYNOjNkJkVoFfKvcBuYqTb4nB0BiKz+nLOXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACxQo3Bb7pkA34OmBADUJz/chBBKBBinSNv/RxnJzb9hToriU/ragR7Gtg6FaCoFSU4EmKlaioZmSbzX81LSCXmvWnt8C/aIPnqFlELWw1c9kKF1rR055mECvJplhYVZus+hhFb9quLNUYxex5zWIqQEol72/7qa8hSa96/yLm0gQu6tSLQXp/8KZt9gXLLO/pW5gUN+hfiMvZyA8UKKCOzdbmgksm0BGGQcLjUH05BH5DA5j1yyNIRluaVHdps1RGd2/5gC4p9E7fWXOSmx0D8KBd+nKSaOtZfGkoTW8o6vNig+p0Ln3bvggcMZWjB2rdTqlkt6WP2pE6j05GpyFpo="
        ],
        "x5t": "sYfQ20Iv2uCNleb4Cj2kvGZ2X00",
        "x5t#S256": "0JvQ117rdJFYNcxkzKZFsYf1jrBiAPiJ1b_HVzIsGyI"
    }*/
    n: String,
    e: String,
}

impl Asymmetric {
    pub async fn new(
        jwk_uri: &str,
        private_key_path: &str,
    ) -> Result<Self, AppStateInitializationError> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let jwks_response = http_client.get(jwk_uri)
            .send()
            .await
                .map_err(|e| AppStateInitializationError::JwksUrlError(e.to_string()))?
            .json::<JwksEndpointResponse>()
            .await
                .map_err(|e| AppStateInitializationError::JwksParseError(e.to_string()))?;
        tracing::info!("got jwks");
        let private_key: Vec<u8> = fs::read(private_key_path).expect("cannot read private_key");
        Ok(Asymmetric {
            jwk_uri: jwk_uri.to_string(),
            e: jwks_response.keys[0].e.clone(),
            n: jwks_response.keys[0].n.clone(),
            private_key,
        })
    }
}

#[async_trait]
impl Authenticator<PongaToken> for Asymmetric {
    async fn verify_jwt(
        &self,
        token: &str,
        aud: &[String]
    ) -> Result<Token<PongaToken>, TokenError> {
        let token: Result<Token<PongaToken>, TokenError> = Token::from_string_jwk(token, &self.n, &self.e, aud).await.into();
        Ok(token?)
    }

    async fn create_jwt(
        &self,
        claims: PongaToken,
    ) -> Result<String, TokenError> {
        let str_token = Token::sign_rsa(&claims, &self.private_key).await?;
        Ok(str_token)
    }
}