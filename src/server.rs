use crate::config::AppConfig;
use crate::feasibility::api;
use crate::feasibility::websocket;
use axum::error_handling::HandleErrorLayer;
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Router};
use axum_oidc::error::MiddlewareError;
use axum_oidc::{EmptyAdditionalClaims, OidcAuthLayer, OidcLoginLayer};
use broadcast::Sender;
use http::Uri;
use log::debug;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite}, Expiry, MemoryStore,
    SessionManagerLayer,
};
use tracing::log;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub(crate) struct ApiContext {
    pub(crate) db: SqlitePool,
    pub(crate) base_url: String,
    pub(crate) sender: Sender<String>,
}

pub async fn serve(config: AppConfig) -> anyhow::Result<()> {
    let filter = format!(
        "{}={level},tower_http={level}",
        env!("CARGO_CRATE_NAME"),
        level = config.log_level
    );
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    let db = SqlitePool::connect("sqlite://db.sqlite?mode=rwc").await?;
    sqlx::migrate!().run(&db).await?;

    // context
    let (sender, _) = broadcast::channel(10);
    let state = Arc::new(ApiContext {
        db: db.clone(),
        base_url: config.base_url.clone(),
        sender,
    });

    // oidc authentication
    // TODO
    // let session_store = MemoryStore::default();
    // let session_layer = SessionManagerLayer::new(session_store)
    //     .with_secure(false)
    //     .with_same_site(SameSite::Lax)
    //     .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));
    //
    // let oidc_login_service = ServiceBuilder::new()
    //     .layer(HandleErrorLayer::new(|e: MiddlewareError| async {
    //         e.into_response()
    //     }))
    //     .layer(OidcLoginLayer::<EmptyAdditionalClaims>::new());
    //
    // let oidc = config.auth.unwrap().oidc.unwrap();
    // let oidc_auth = ServiceBuilder::new()
    //     .layer(HandleErrorLayer::new(|e: MiddlewareError| async {
    //         e.into_response()
    //     }))
    //     .layer(
    //         OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
    //             Uri::from_maybe_shared(config.base_url)?,
    //             oidc.issuer.unwrap(),
    //             oidc.client_id.unwrap(),
    //             Some(oidc.client_secret.unwrap()),
    //             vec![],
    //         )
    //         .await?,
    //     );

    let router = api_router(state);
    // let oidc_services = ServiceBuilder::new()
    //     .layer(oidc_login_service)
    //     .layer(oidc_auth)
    //     .layer(session_layer);
    //
    //                         .layer(oidc_login_service)
    //                             .layer(oidc_auth)
    //                             .layer(session_layer););

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    debug!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router).await.map_err(|e| e.into())
}

async fn root() -> &'static str {
    "Machbarkeit Web API"
}

fn api_router(state: Arc<ApiContext>) -> Router {
    Router::new()
        .route("/", get(root))
        .merge(api::router())
        .merge(websocket::router())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[sqlx::test]
    async fn root_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
        });

        // test server
        let router = api_router(state);
        let server = TestServer::new(router).unwrap();

        // send request
        let response = server.get("/").await;

        // assert
        response.assert_status_ok();
        response.assert_text("Machbarkeit Web API");
    }
}
