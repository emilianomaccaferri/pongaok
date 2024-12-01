use std::{env, sync::Arc};

use rqlite_rs::{RqliteClient, RqliteClientBuilder};
use thiserror::Error;

use crate::auth_mode::AuthMode;

use super::{authenticator::{asymmetric::Asymmetric, symmetric::Symmetric, Authenticator}, extractors::token::PongaToken};

#[derive(Clone)]
pub struct AppState {
    pub rqlite: Arc<RqliteClient>,
    pub authenticator: Arc<Box<dyn Authenticator<PongaToken>>>,
}

#[derive(Error, Debug, Clone)]
pub enum AppStateInitializationError {
    #[error("error while querying the jwks uri: {0}")]
    JwksUrlError(String),
    #[error("error while parsing the jwk object: {0}")]
    JwksParseError(String)
}


impl AppState {
    pub async fn new(auth_mode: AuthMode) -> Result<Self, AppStateInitializationError> {

        let rqlite = RqliteClientBuilder::new()
            .known_host(
                env::var("RQLITE_HOST").expect("RQLITE_HOST is not defined")
            )
            .auth(
                env::var("RQLITE_USER").expect("RQLITE_USER is not defined").as_str(),
                env::var("RQLITE_PASSWORD").expect("RQLITE_PASSWORD is not defined").as_str()
            )
            .build()
            .expect("rqlite client");
        
        let state = match auth_mode {
            AuthMode::Asymmetric => {
                let jwk_uri= env::var("JWK_URI").expect("JWK_URI is not defined").to_string();
                let private_key_path= env::var("PRIVATE_KEY_PATH").expect("PRIVATE_KEY_PATH is not defined").to_string();
                Ok(AppState {
                    rqlite: Arc::new(rqlite),
                    authenticator: Arc::new(
                        Box::new(Asymmetric::new(&jwk_uri, &private_key_path).await?
                        ),
                    )
                })
            },
            AuthMode::Symmetric => {
                Ok(AppState {
                    rqlite: Arc::new(rqlite),
                    authenticator: Arc::new(
                        Box::new(Symmetric::new())
                    )
                })
            }
        };

        state
    }
}