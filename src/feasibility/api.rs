use axum::extract::{Path, State};
use axum::{debug_handler, Json, Router};
use http::{header, StatusCode};

use crate::error::ApiError;
use crate::server::ApiContext;
use anyhow::anyhow;
use axum::extract::ws::Utf8Bytes;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use http::header::LOCATION;
use serde_derive::{Deserialize, Serialize};
use sqlx::types::{JsonValue, Uuid};
use sqlx::FromRow;
use std::sync::Arc;

pub(crate) fn router() -> Router<Arc<ApiContext>> {
    Router::new()
        .route("/feasibility/request", post(create))
        .route("/feasibility/request/{id}", get(read))
}

#[derive(Clone, Debug, PartialEq, PartialOrd, sqlx::Type, Deserialize, Serialize)]
#[sqlx(type_name = "status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub(crate) enum QueryState {
    Pending,
    Completed,
}

impl Into<String> for QueryState {
    fn into(self) -> String {
        match self {
            QueryState::Pending => "pending".to_string(),
            QueryState::Completed => "completed".to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, FromRow, Debug, PartialEq, Clone)]
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
}

#[debug_handler]
async fn create(
    State(ctx): State<Arc<ApiContext>>,
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
    };

    let result: FeasibilityRequest = sqlx::query_as!(
        FeasibilityRequest,
        r#"insert into requests (id,date,query,status,result_code,result_body,result_duration) values ($1,$2,$3,$4,$5,$6,$7)
           returning id as "id!:_",date as "date!:_" ,query as "query!:_",
                     status as "status!:_", result_code as "result_code:_",result_body,result_duration as "result_duration:_""#,
        request.id,
        request.date,
        request.query,
        request.status,
        request.result_code,
        request.result_body,
        request.result_duration,
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

#[debug_handler]
async fn read(
    State(ctx): State<Arc<ApiContext>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let result:Option<FeasibilityRequest> = sqlx::query_as!(
        FeasibilityRequest,
        r#"select id as "id!:_",date as "date!:_" ,query as "query!:_",status as "status!:_",result_code as "result_code:_",result_body,result_duration as "result_duration:_"
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

pub(crate) async fn store_result(
    msg: Utf8Bytes,
    state: Arc<ApiContext>,
) -> Result<(), anyhow::Error> {
    let request = serde_json::from_str::<FeasibilityRequest>(&msg)?;

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
            .with_state(state);
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .unwrap();

        let mut websocket = server
            .get_websocket(&"/feasibility/ws")
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
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }
}
