use crate::config::AppConfig;
use crate::feasibility::api;
use crate::feasibility::websocket;
use auth::users::Backend;
use axum::{routing::get, Router};
use axum_login::{login_required, AuthManagerLayerBuilder};
use broadcast::Sender;
use http::HeaderValue;
use log::debug;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite}, Expiry, MemoryStore,
    SessionManagerLayer,
};
use tracing::log;
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

    let router = api_router(state, config)
        .await
        .expect("Failed to create router");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    debug!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router).await.map_err(|e| e.into())
}

async fn root() -> &'static str {
    "Machbarkeit Web API"
}

async fn api_router(state: Arc<ApiContext>, config: AppConfig) -> Result<Router, anyhow::Error> {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    let oidc_config = config.auth.unwrap().oidc.unwrap();

    let client_id = oidc_config
        .client_id
        .map(ClientId::new)
        .expect("CLIENT_ID should be provided.");
    let client_secret = oidc_config
        .client_secret
        .map(ClientSecret::new)
        .expect("CLIENT_SECRET should be provided.");

    let auth_url = AuthUrl::new(oidc_config.auth_endpoint.unwrap())?;
    let token_url = TokenUrl::new(oidc_config.token_endpoint.unwrap())?;

    let client = BasicClient::new(client_id)
        .set_client_secret(client_secret)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(RedirectUrl::new(
            "http://localhost:3000/oauth/callback".to_string(),
        )?);

    // todo
    let db = SqlitePool::connect(":memory:").await?;

    let backend = Backend::new(db, client, oidc_config.userinfo_endpoint.unwrap()).await;
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    Ok(Router::new()
        .route("/", get(root))
        .merge(
            api::router()
                .route_layer(login_required!(Backend, login_url = "/login"))
                .merge(crate::auth::router())
                .layer(auth_layer),
        )
        .merge(websocket::router())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(
                    config
                        .cors
                        .unwrap()
                        .allow_origin
                        .unwrap()
                        .parse::<HeaderValue>()?,
                )
                .allow_credentials(true),
        ))
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
        let router = api_router(state, AppConfig::default()).await.unwrap();
        let server = TestServer::new(router).unwrap();

        // send request
        let response = server.get("/").await;

        // assert
        response.assert_status_ok();
        response.assert_text("Machbarkeit Web API");
    }
}
