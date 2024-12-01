use std::collections::HashMap;

use axum::{extract::rejection::JsonRejection, http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use validator::ValidationErrorsKind;

pub enum HttpError {
    ParsingError(String, StatusCode),
    InvalidFieldsError(HashMap<&'static str, ValidationErrorsKind>),
    Simple(StatusCode, String),
    DatabaseError
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let tuple_response = match self {
            HttpError::ParsingError(text, _) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"success": false, "error": text})),
            ),
            HttpError::InvalidFieldsError(err) => {
                let invalid_fields: Vec<&str> =
                    err.into_keys().map(|i| i).collect();
                (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"success": false, "error": "invalid_fields", "fields": invalid_fields}),
                    ),
                )
            }
            HttpError::Simple(code, msg) => {
                (code, Json(json!({ "success": false, "error": msg })))
            }
            HttpError::DatabaseError => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "success": false, "error": "fatal_error" })))
            }
        };

        tuple_response.into_response()
    }
}

impl From<JsonRejection> for HttpError {
    // error while parsing invalid json
    fn from(err: JsonRejection) -> Self {
        Self::ParsingError("invalid_body".to_owned(), err.status())
    }
}

impl From<validator::ValidationErrors> for HttpError {
    // error when validating structs
    fn from(err: validator::ValidationErrors) -> Self {
        Self::InvalidFieldsError(err.into_errors())
    }
}
impl From<tokio::task::JoinError> for HttpError {
    // this is tokio's blocking task error
    fn from(_: tokio::task::JoinError) -> Self {
        Self::Simple(StatusCode::INTERNAL_SERVER_ERROR, "async_error".to_string())
    }
}
impl From<jsonwebtoken::errors::Error> for HttpError {
    fn from(_e: jsonwebtoken::errors::Error) -> Self {
        Self::Simple(StatusCode::INTERNAL_SERVER_ERROR, "bad_jwt".to_string())
    }
}

impl From<rqlite_rs::error::RequestError> for HttpError {
    fn from(error: rqlite_rs::error::RequestError) -> Self {
        Self::Simple(StatusCode::INTERNAL_SERVER_ERROR, format!("bad_rqlite_request: {}", error.to_string()))
    }
}
