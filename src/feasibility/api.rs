use axum::extract::{Path, State};
use axum::{Json, Router, debug_handler};
use http::{StatusCode, header};
use std::cmp::max;

use crate::error::ApiError;
use crate::server::ApiContext;
use anyhow::anyhow;
use auth::users::AuthSession;
use axum::extract::ws::Utf8Bytes;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum_extra::extract::OptionalQuery;
use axum_login::AuthUser;
use chrono::{DateTime, Utc};
use http::header::LOCATION;
use log::info;
use serde_derive::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::types::{JsonValue, Uuid};
use std::sync::Arc;
use utoipa::ToSchema;

pub(crate) fn router() -> Router<Arc<ApiContext>> {
    Router::new()
        .route("/feasibility/request", post(create))
        .route("/feasibility/request/{id}", get(read))
        .route("/feasibility/request", get(read_all))
}

#[derive(ToSchema, Clone, Debug, PartialEq, PartialOrd, sqlx::Type, Deserialize, Serialize)]
#[sqlx(type_name = "status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub(crate) enum QueryState {
    Pending,
    Completed,
}

#[derive(ToSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ResultState {
    Pending,
    Completed,
    Error,
}

impl Into<String> for QueryState {
    fn into(self) -> String {
        match self {
            QueryState::Pending => "pending".to_string(),
            QueryState::Completed => "completed".to_string(),
        }
    }
}

#[derive(ToSchema, Deserialize, Serialize, FromRow, Debug, PartialEq, Clone)]
pub(crate) struct FeasibilityRequest {
    pub(crate) id: Uuid,
    date: DateTime<Utc>,
    query: JsonValue,
    pub(crate) status: QueryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result_duration: Option<u32>,
    #[serde(skip)]
    user_id: Option<i64>,
}

#[derive(ToSchema, Serialize)]
pub(crate) struct FeasibilityResult {
    pub(crate) id: Uuid,
    date: DateTime<Utc>,
    query: JsonValue,
    pub(crate) status: ResultState,
    pub(crate) result: Option<u32>,
    pub(crate) duration: u32,
}

impl From<FeasibilityRequest> for FeasibilityResult {
    fn from(request: FeasibilityRequest) -> Self {
        FeasibilityResult {
            id: request.id,
            date: request.date,
            query: request.query,
            status: match (request.result_code, request.status) {
                (_, QueryState::Pending) => ResultState::Pending,
                (Some(200), QueryState::Completed) => ResultState::Completed,
                (_, QueryState::Completed) => ResultState::Error,
            },
            result: request.result_body.and_then(|r| r.parse().ok()),
            duration: request.result_duration.unwrap_or_default(),
        }
    }
}

/// Create a Feasibility request
#[utoipa::path(
    post,
    path = "/feasibility/request",
    request_body(content = JsonValue, content_type = "application/sq+json"),
    responses(
        (
            status = 203,
            description = "Request accepted. See Location header for result",
            headers(
                ("Location" = String, description = "Result endpoint for the request")
            ),
            body = FeasibilityRequest,
        ),
        (
            status = 503, description = "No feasibility service subscribed to execute the query",
            body = String
        )
    ),
    tag = "feasibility"
)]
#[debug_handler]
pub(crate) async fn create(
    State(ctx): State<Arc<ApiContext>>,
    auth_session: Result<AuthSession, (StatusCode, &'static str)>,
    Json(query): Json<JsonValue>,
) -> Result<impl IntoResponse, ApiError> {
    if ctx.sender.receiver_count() < 1 {
        return Err(ApiError(
            anyhow!("No feasibility service subscribed to execute the query"),
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }

    let request = FeasibilityRequest {
        id: Uuid::new_v4(),
        date: Utc::now(),
        query,
        status: QueryState::Pending,
        result_code: None,
        result_body: None,
        result_duration: None,
        user_id: auth_session.ok().and_then(|a| a.user.map(|u| u.id())),
    };

    info!("Create feasibility request: id={}", request.id);

    let result: FeasibilityRequest = sqlx::query_as!(
        FeasibilityRequest,
        r#"insert into requests (id,date,query,status,result_code,result_body,result_duration,user_id) values ($1,$2,$3,$4,$5,$6,$7,$8)
           returning id as "id!:_",date as "date!:_" ,query as "query!:_",
                     status as "status!:_", result_code as "result_code:_",result_body,result_duration as "result_duration:_", user_id"#,
        request.id,
        request.date,
        request.query,
        request.status,
        request.result_code,
        request.result_body,
        request.result_duration,
        request.user_id
    )
        .fetch_one(&ctx.db)
        .await?;

    // broadcast request
    let msg = serde_json::to_string(&request)?;
    ctx.sender.send(msg)?;

    let resource_uri: String =
        format!("{}/feasibility/request/{}", ctx.base_url, request.id).parse()?;

    Ok((
        StatusCode::ACCEPTED,
        [(LOCATION, resource_uri)],
        Json(result),
    ))
}

/// Get a Feasibility result by id
#[utoipa::path(
    get,
    path = "/feasibility/request/{id}",
    responses(
        (status = 200, description = "Ok", body = FeasibilityRequest),
        (status = 404, description = "Not Found. Result is not available yet", body = ()),
        (status = 503, description = "Service Unavailable", body = String),
        (status = 504, description = "Gateway Timeout", body = String),
        (status = 500, description = "Internal Server Error", body = String)
    ),
    tag = "feasibility"
)]
#[debug_handler]
pub(crate) async fn read(
    State(ctx): State<Arc<ApiContext>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let result: Option<FeasibilityRequest> = sqlx::query_as!(
        FeasibilityRequest,
        r#"select id as "id!:_",
        date as "date!:_" ,
        query as "query!:_",
        status as "status!:_",
        result_code as "result_code:_",
        result_body,result_duration as "result_duration:_",
        user_id
        from requests where id = $1"#,
        id
    )
        .fetch_optional(&ctx.db)
        .await?;
    match result {
        Some(r) => match r.status {
            QueryState::Pending => Ok(StatusCode::NOT_FOUND.into_response()),
            QueryState::Completed => {
                let body = r.result_body.clone().unwrap_or_default();
                let resp = (
                    StatusCode::from_u16(r.result_code.unwrap_or(StatusCode::FOUND.as_u16()))
                        .unwrap_or(StatusCode::FOUND),
                    [(header::CONTENT_TYPE, "text/plain")],
                    body,
                )
                    .into_response();

                Ok(resp)
            }
        },
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

/// Get Feasibility requests for a user
#[utoipa::path(
    get,
    path = "/feasibility/request",
    responses(
        (status = 200, description = "Ok", body = Vec<FeasibilityResult>),
        (status = 401, description = "Unauthorized", body = String),
    ),
    tag = "feasibility"
)]
#[debug_handler]
pub(crate) async fn read_all(
    auth_session: AuthSession,
    State(ctx): State<Arc<ApiContext>>,
    OptionalQuery(limit): OptionalQuery<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = auth_session
        .user
        .map(|u| u.id())
        .ok_or(anyhow!("Failed to extract user from session"))
        .map_err(|e| ApiError(e, StatusCode::UNAUTHORIZED))?;

    let limit = max(limit.unwrap_or(20), 20);

    Ok(Json(
        sqlx::query_as!(
            FeasibilityRequest,
            r#"select r.id as "id!:_",
        r.date as "date!:_" ,
        r.query as "query!:_",
        r.status as "status!:_",
        r.result_code as "result_code:_",
        r.result_body,result_duration as "result_duration:_",
        r.user_id
        from requests r inner join users u on r.user_id = u.id where r.user_id = $1 order by r.date desc limit $2"#,
            user_id,
            limit
        )
            .fetch_all(&ctx.db)
            .await?.into_iter().map(FeasibilityResult::from).collect::<Vec<_>>(),
    ))
}

pub(crate) async fn store_result(
    msg: Utf8Bytes,
    state: Arc<ApiContext>,
) -> Result<(), anyhow::Error> {
    let request = serde_json::from_str::<FeasibilityRequest>(&msg)?;
    info!("Storing feasibility result: id={}", request.id);

    sqlx::query_as!(
        FeasibilityRequest,
        r#"update requests set
           status = $1, result_code = $2, result_body = $3, result_duration = $4
           where id = $5"#,
        request.status,
        request.result_code,
        request.result_body,
        request.result_duration,
        request.id
    )
        .execute(&state.db)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_oidc_jwt_validator::{OidcConfig, OidcValidator};
    use auth::users::Backend;
    use axum::body::Body;
    use axum_login::AuthManagerLayerBuilder;
    use axum_test::TestServer;
    use header::CONTENT_TYPE;
    use http::{HeaderValue, Request};
    use http_body_util::BodyExt;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use oauth2::basic::BasicClient;
    use oauth2::reqwest::Url;
    use oauth2::{AuthUrl, ClientId, TokenUrl};
    use serde_json::{Value, json};
    use sqlx::SqlitePool;
    use std::net::SocketAddr;
    use tokio::sync::broadcast;
    use tokio::time::timeout;
    use tower::util::ServiceExt;
    use tower_sessions::{MemoryStore, SessionManagerLayer};

    #[sqlx::test]
    async fn create_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
            auth: None,
            mdr_endpoint: None,
        });

        // test server
        let router = crate::feasibility::websocket::router()
            .merge(router())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .unwrap();

        let mut websocket = server
            .get_websocket("/feasibility/ws")
            .await
            .into_websocket()
            .await;

        // dummy request data
        let query = JsonValue::Object(Default::default());

        // send request
        let response = server
            .post("/feasibility/request")
            .json(&query.clone())
            .await;

        let ws_msg: FeasibilityRequest =
            tokio::spawn(timeout(std::time::Duration::from_secs(30), async move {
                let msg = websocket.receive_text().await;
                serde_json::from_str(msg.as_str()).unwrap()
            }))
                .await
                .unwrap()
                .expect("timeout receiving data from websocket");

        // assert
        response.assert_status(StatusCode::ACCEPTED);
        response.assert_contains_header(LOCATION);
        response.assert_json(&ws_msg);
    }

    #[sqlx::test]
    async fn create_service_unavailable_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
            auth: None,
            mdr_endpoint: None,
        });

        // test server
        let router = router().with_state(state);
        let server = TestServer::new(router).unwrap();

        // dummy request data
        let query = JsonValue::Object(Default::default());

        // send request
        let response = server
            .post("/feasibility/request")
            .json(&query.clone())
            .await;

        // assert
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[sqlx::test(fixtures("../fixtures/requests.sql"))]
    async fn read_all_test(pool: SqlitePool) {
        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
            auth: None,
            mdr_endpoint: None,
        });

        // mock idp (and respective client) to simulate user authentication
        let idp = mock_idp();
        let client = BasicClient::new(ClientId::new("test".to_string()))
            .set_auth_uri(AuthUrl::new(format!("{}/auth", idp.base_url()).to_string()).unwrap())
            .set_token_uri(TokenUrl::new(format!("{}/token", idp.base_url()).to_string()).unwrap());

        let backend = Backend::new(
            state.db.clone(),
            client.clone(),
            format!("{}/userinfo", idp.base_url()),
            OidcValidator::new(OidcConfig::new(String::new(), String::new(), String::new())),
        )
            .await;

        // auth layer
        let auth_layer =
            AuthManagerLayerBuilder::new(backend, SessionManagerLayer::new(MemoryStore::default()))
                .build();

        // router with auth layer
        let router = router()
            .merge(crate::auth::router())
            .layer(auth_layer)
            .with_state(state);

        // login to get a user session
        let cookie = oauth_login(&router).await;

        // feasibility request (with session cookie)
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .header(header::COOKIE, cookie)
                    .uri("/feasibility/request")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        println!("{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body,
            json!([
                {
                    "id":"39613561-3764-3163-3434-343834636663",
                    "date":"2026-04-01T22:00:00Z",
                    "query": {},
                    "status": "pending",
                    "duration": 0,
                    "result": null,
                },
                {
                    "id":"30623665-3632-6363-6634-653332386365",
                    "date":"2026-01-01T10:00:00Z",
                    "query": {},
                    "status": "completed",
                    "result": 42,
                    "duration": 0,
                }
            ])
        )
    }

    fn mock_idp() -> MockServer {
        let server = MockServer::start();

        // token endpoint
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header(CONTENT_TYPE.as_str(), "application/json")
                .json_body(json!({
                    "token_type": "Bearer",
                    "access_token": "eyJ...",
                }));
        });

        // userinfo
        server.mock(|when, then| {
            when.method(GET).path("/userinfo");
            then.status(200)
                .header(CONTENT_TYPE.as_str(), "application/json")
                .json_body(json!({
                    "name": "Test",
                    "email": "Test",
                }));
        });

        server
    }

    async fn oauth_login(router: &Router) -> HeaderValue {
        // login to get a user session
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // get redirect location header
        let redirect_target = response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap();
        let target_url: Url = redirect_target.parse().unwrap();
        let state = target_url
            .query_pairs()
            .find_map(|(k, v)| if k == "state" { Some(v) } else { None })
            .unwrap();
        let cookie = response.headers().get(header::SET_COOKIE).unwrap();

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .header(header::COOKIE, cookie)
                    .uri(format!("/oauth/callback?code=test&state={state}"))
                    .method("GET")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // return cookie
        response.headers().get(header::SET_COOKIE).unwrap().clone()
    }
}
