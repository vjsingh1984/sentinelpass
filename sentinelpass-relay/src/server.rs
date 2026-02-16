//! Axum router setup.

use crate::auth::auth_middleware;
use crate::config::RelayConfig;
use crate::handlers::{devices, pairing, sync};
use crate::storage::RelayStorage;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub fn build_router(storage: RelayStorage, config: &RelayConfig) -> Router {
    // Authenticated routes
    let authenticated = Router::new()
        .route("/api/v1/devices", get(devices::list_devices))
        .route("/api/v1/devices/{id}/revoke", post(devices::revoke_device))
        .route("/api/v1/sync/push", post(sync::push))
        .route("/api/v1/sync/pull", post(sync::pull))
        .route("/api/v1/sync/full-push", post(sync::full_push))
        .route("/api/v1/sync/full-pull", post(sync::full_pull))
        .route("/api/v1/sync/status", get(sync::status))
        .layer(middleware::from_fn_with_state(
            storage.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes
    let public = Router::new()
        .route("/api/v1/devices/register", post(devices::register_device))
        .route("/api/v1/pairing/bootstrap", post(pairing::upload_bootstrap))
        .route(
            "/api/v1/pairing/bootstrap/{token}",
            get(pairing::fetch_bootstrap),
        )
        .route("/health", get(health));

    Router::new()
        .merge(authenticated)
        .merge(public)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(config.max_payload_size))
        .with_state(storage)
}

async fn health() -> &'static str {
    "ok"
}
