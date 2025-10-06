use crate::auth::auth_middleware;
use crate::config::{AppConfig, Auth, Cors};
use crate::feasibility::api;
use crate::feasibility::websocket;
use async_oidc_jwt_validator::{OidcConfig, OidcValidator};
use auth::oidc::DiscoveryDocument;
use auth::users::Backend;
use axum::routing::get;
use axum::{middleware, Router};
use axum_login::AuthManagerLayerBuilder;
use axum_reverse_proxy::ReverseProxy;
use broadcast::Sender;
use http::header::{AUTHORIZATION, CONTENT_TYPE, LOCATION};
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
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{openapi, Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

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

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    security(
         ("Access token" = []),
    ),
    paths(root, api::read, api::create)
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        openapi.components = Some(
            openapi::ComponentsBuilder::new()
                .security_scheme(
                    "Access token",
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .bearer_format("JWT")
                            .build(),
                    ),
                )
                .build(),
        )
    }
}

/// API metadata
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Machbarkeit Web API", body = str),
    ),
    tag = "metadata"
)]
async fn root() -> &'static str {
    "Machbarkeit Web API"
}

async fn build_router(state: Arc<ApiContext>, config: &AppConfig) -> Result<Router, anyhow::Error> {
    let router = Router::new()
        .route("/", get(root))
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi())
                .config(
                    utoipa_swagger_ui::Config::default()
                        .try_it_out_enabled(true)
                        .filter(false),
                ),
        )
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
            .expose_headers([LOCATION])
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
            .with_secure(config.session.cross_domain)
            .with_same_site(if config.session.cross_domain {
                SameSite::None
            } else {
                SameSite::Lax
            })
            .with_expiry(Expiry::OnInactivity(Duration::seconds(
                config.session.lifetime,
            )));

        let client_id = ClientId::new(oidc_config.client_id.clone());
        let client_secret = ClientSecret::new(oidc_config.client_secret);
        let discovery: DiscoveryDocument = DiscoveryDocument::new(&oidc_config.issuer_url).await?;

        let auth_url = AuthUrl::new(discovery.authorization_endpoint)?;
        let token_url = TokenUrl::new(discovery.token_endpoint)?;

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
            oidc_config.issuer_url,
            oidc_config.client_id,
            discovery.jwks_uri,
        );
        let validator = OidcValidator::new(validation_config);

        let backend = Backend::new(
            state.db.clone(),
            client,
            discovery.userinfo_endpoint,
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
    use crate::config::{Auth, Oidc, Session};
    use axum_test::TestServer;
    use http::header::ORIGIN;
    use http::StatusCode;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use serde_json::json;
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

        // mock server for the oidc discovery
        let idp = MockServer::start();

        // config
        let config = AppConfig {
            log_level: "debug".to_string(),
            base_url: "http://localhost".to_string(),
            auth: Some(Auth {
                oidc: Some(Oidc {
                    client_id: "test_client".to_string(),
                    client_secret: "test_secret".to_string(),
                    issuer_url: idp.base_url(),
                }),
            }),
            cors: Some(Cors {
                allow_origin: Some("http://localhost:5443".to_string()),
            }),
            mdr: None,
            session: Session {
                lifetime: 120,
                cross_domain: false,
            },
        };

        // discovery endpoint mock
        let discovery_mock = idp.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "issuer": idp.base_url(),
                    "authorization_endpoint": format!("{}/auth", idp.base_url()),
                    "token_endpoint": format!("{}/token", idp.base_url()),
                    "introspection_endpoint": format!("{}/introspect", idp.base_url()),
                    "userinfo_endpoint": format!("{}/userinfo", idp.base_url()),
                    "jwks_uri": format!("{}/certs", idp.base_url()),
                }));
        });

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

        // assert oidc discovery
        discovery_mock.assert();

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
