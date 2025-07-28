use crate::config::AppConfig;
use crate::feasibility;
use axum::{routing::get, Router};
use broadcast::Sender;
use log::debug;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
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
        level = config.app.log_level
    );
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    let db = SqlitePool::connect("sqlite://db.sqlite?mode=rwc").await?;

    let (sender, _) = broadcast::channel(10);
    let state = Arc::new(ApiContext {
        db: db.clone(),
        base_url: config.base_url,
        sender,
    });
    let router = api_router(state);

    sqlx::migrate!().run(&db).await?;

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
        .merge(feasibility::router())
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
