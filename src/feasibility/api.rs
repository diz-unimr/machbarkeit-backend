use axum::extract::{Path, State};
use axum::{debug_handler, Json, Router};
use http::{header, StatusCode};
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
use sqlx::types::{JsonValue, Uuid};
use sqlx::FromRow;
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

    let limit = max(limit.unwrap_or(50), 50);

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
    use axum_test::TestServer;
    use sqlx::SqlitePool;
    use std::net::SocketAddr;
    use tokio::sync::broadcast;

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

        let ws_msg: FeasibilityRequest = tokio::spawn(async move {
            let msg = websocket.receive_text().await;
            serde_json::from_str(msg.as_str()).unwrap()
        })
        .await
        .unwrap();

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
        println!("{:?}", response.text());
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }
}
