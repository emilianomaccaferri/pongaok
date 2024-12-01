use std::env;

use tracing_subscriber::fmt::format::FmtSpan;

mod web;
mod auth_mode;

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default");

    let router = web::app::build().await;
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", env::var("HTTP_PORT").unwrap_or("3000".to_string()))).await.unwrap();
    tracing::info!("axum listener bound");
    axum::serve(listener, router)
        .await
        .unwrap();
}