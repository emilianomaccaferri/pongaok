use std::{convert::Infallible, env};

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use crate::auth_mode::AuthMode;

use super::app_state::AppState;

/// creates the main router and panics if env variables are not set
pub async fn build() -> Router {
    let auth_mode_str = env::var("AUTH_MODE").expect("AUTH_MODE env variable is not defined");
    let auth_mode = serde_json::from_str::<AuthMode>(&auth_mode_str)
        .expect("invalid auth mode: only 'asymmetric' and 'symmetric' are allowed");
    let state = AppState::new(auth_mode).await;
        let app = Router::new()
        .route("/", get(main_route))
        .with_state(state.clone());

    app
}

async fn main_route() -> Result<Json<Value>, Infallible> {
    Ok(
        Json(
            json!({
                "success": true,
                "version": "0.0.1",
            })
        )
    )
}