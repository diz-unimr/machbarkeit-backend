use crate::auth::auth_middleware;
use crate::config::{AppConfig, Auth, Cors};
use crate::feasibility::api;
use crate::feasibility::websocket;
use async_oidc_jwt_validator::{OidcConfig, OidcValidator};
use auth::users::Backend;
use axum::{middleware, routing::get, Router};
use axum_login::AuthManagerLayerBuilder;
use axum_reverse_proxy::ReverseProxy;
use broadcast::Sender;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::method::Method;
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
    pub(crate) auth: Option<Auth>,
    pub(crate) mdr_endpoint: Option<String>,
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
        auth: config.auth.clone(),
        mdr_endpoint: config.mdr.clone().map(|m| m.endpoint),
    });

    let router = build_router(state, &config)
        .await
        .expect("Failed to create router");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    debug!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router).await.map_err(|e| e.into())
}

async fn root() -> &'static str {
    "Machbarkeit Web API"
}

async fn build_router(state: Arc<ApiContext>, config: &AppConfig) -> Result<Router, anyhow::Error> {
    let router = Router::new()
        .route("/", get(root))
        .merge(build_api_router(state.clone(), config).await?)
        .with_state(state)
        .layer(build_cors_layer(config.clone().cors)?)
        .layer(TraceLayer::new_for_http());

    Ok(router)
}

fn build_cors_layer(config: Option<Cors>) -> Result<CorsLayer, anyhow::Error> {
    if let Some(origin) = config.and_then(|c| c.allow_origin) {
        let origins = origin
            .split(",")
            .map(|o| o.parse::<HeaderValue>().unwrap())
            .collect::<Vec<HeaderValue>>();

        Ok(CorsLayer::new()
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_origin(origins)
            .allow_headers([AUTHORIZATION, CONTENT_TYPE]))
    } else {
        Ok(CorsLayer::default())
    }
}

async fn build_api_router(
    state: Arc<ApiContext>,
    config: &AppConfig,
) -> Result<Router<Arc<ApiContext>>, anyhow::Error> {
    let mut router = api::router().merge(websocket::router());

    if let Some(mdr) = &state.mdr_endpoint {
        router = router.merge(ReverseProxy::new("/mdr", mdr.as_str()));
    }

    // oidc auth
    if let Some(oidc_config) = config.clone().auth.and_then(|auth| auth.oidc) {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_same_site(SameSite::Lax)
            .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

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
            .set_redirect_uri(RedirectUrl::new(format!(
                "{}/oauth/callback",
                config.base_url
            ))?);

        // jwt validation config
        let validation_config = OidcConfig::new(
            "https://idp.diz.uni-marburg.de/auth/realms/Miracum".to_string(),
            "machbarkeit".to_string(),
            "https://idp.diz.uni-marburg.de/auth/realms/Miracum/protocol/openid-connect/certs"
                .to_string(),
        );
        let validator = OidcValidator::new(validation_config);
        let db = SqlitePool::connect(":memory:").await?;
        let backend = Backend::new(
            db,
            client,
            oidc_config.userinfo_endpoint.unwrap(),
            validator,
        )
        .await;
        let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

        Ok(router
            .layer(middleware::from_fn_with_state(state, auth_middleware))
            .merge(crate::auth::router())
            .layer(auth_layer))
    } else {
        Ok(router)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Auth, Oidc};
    use axum_test::TestServer;
    use http::header::ORIGIN;
    use http::StatusCode;
    use urlencoding::Encoded;

    #[sqlx::test]
    async fn root_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
            auth: None,
            mdr_endpoint: None,
        });

        // test server
        let router = build_router(state, &AppConfig::default()).await.unwrap();
        let server = TestServer::new(router).unwrap();

        // send request
        let response = server.get("/").await;

        // assert
        response.assert_status_ok();
        response.assert_text("Machbarkeit Web API");
    }

    #[sqlx::test]
    async fn auth_config_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
            auth: None,
            mdr_endpoint: None,
        });
        let config = AppConfig {
            log_level: "debug".to_string(),
            base_url: "http://localhost".to_string(),
            auth: Some(Auth {
                oidc: Some(Oidc {
                    client_id: Some("test_client".to_string()),
                    client_secret: Some("test_secret".to_string()),
                    auth_endpoint: Some("http://localhost/dummy/auth".to_string()),
                    token_endpoint: Some("http://localhost/dummy/token".to_string()),
                    userinfo_endpoint: Some("http://localhost/dummy/userinfo".to_string()),
                }),
            }),
            cors: Some(Cors {
                allow_origin: Some("http://localhost:5443".to_string()),
            }),
            mdr: None,
        };

        // test server
        let router = build_router(state, &config).await.unwrap();
        let server = TestServer::new(router).unwrap();

        // send request
        let req_url = "/feasibility/request";
        let response = server
            .post(req_url)
            // send origin
            .add_header(ORIGIN, config.cors.clone().unwrap().allow_origin.unwrap())
            .await;

        // assert redirect to auth server
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        response.assert_header(
            "location",
            format!(
                "/login?next={}",
                Encoded(config.base_url.to_owned() + req_url).to_string()
            )
            .to_string(),
        );

        // cors header is set
        response.assert_header(
            "access-control-allow-origin",
            config.cors.unwrap().allow_origin.unwrap(),
        );
    }
}
