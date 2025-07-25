use axum::extract::{State, WebSocketUpgrade};
use axum::{debug_handler, Json, Router};
use http::StatusCode;

use crate::error::ApiError;
use crate::server::ApiContext;
use anyhow::anyhow;
use axum::extract::ws::{Message, WebSocket};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use futures_util::{
    sink::SinkExt,
    stream::{SplitStream, StreamExt},
};
use http::header::LOCATION;
use serde_derive::{Deserialize, Serialize};
use sqlx::types::Uuid;
use sqlx::FromRow;
use std::sync::Arc;
use tracing::log::{debug, info};

pub(crate) fn router() -> Router<Arc<ApiContext>> {
    Router::new()
        .route("/feasibility/request", post(create))
        .route("/feasibility/ws", get(ws_handler))
}

#[derive(Clone, Debug, PartialEq, PartialOrd, sqlx::Type, Deserialize, Serialize)]
#[sqlx(type_name = "status", rename_all = "lowercase")]
enum QueryState {
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

#[derive(Deserialize, Serialize, FromRow, Debug, PartialEq)]
struct FeasibilityRequest {
    id: Uuid,
    date: DateTime<Utc>,
    query: sqlx::types::Json<FeasibilityQuery>,
    status: QueryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize, Serialize, FromRow, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FeasibilityQuery {
    version: String,
    display: String,
    inclusion_criteria: Vec<Vec<Criterion>>,
    exclusion_criteria: Vec<Vec<String>>,
}

impl Into<FeasibilityRequest> for FeasibilityQuery {
    fn into(self) -> FeasibilityRequest {
        FeasibilityRequest {
            id: Default::default(),
            date: Default::default(),
            query: sqlx::types::Json(self),
            status: QueryState::Pending,
            result: None,
            duration: None,
            error: None,
        }
    }
}

#[derive(Deserialize, Serialize, FromRow, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Criterion {
    id: String,
    term_codes: Vec<Coding>,
    context: Module,
    time_restriction: Option<TimeConstraint>,
}

#[derive(Deserialize, Serialize, FromRow, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct TimeConstraint {
    before_date: Option<String>,
    after_date: Option<String>,
}

#[derive(Deserialize, Serialize, FromRow, Clone, Debug, PartialEq)]
struct Coding {
    code: String,
    system: String,
    display: String,
    version: Option<String>,
}

#[derive(Deserialize, Serialize, FromRow, Clone, Debug, PartialEq)]
struct Module {
    code: String,
    system: String,
    display: String,
    version: Option<String>,
}

#[debug_handler]
async fn create(
    State(ctx): State<Arc<ApiContext>>,
    Json(query): Json<FeasibilityQuery>,
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
        query: sqlx::types::Json(query),
        status: QueryState::Pending,
        result: None,
        duration: None,
        error: None,
    };

    let result: FeasibilityRequest = sqlx::query_as!(
        FeasibilityRequest,
        // r#"insert into requests (id,date,query,status,result,duration,error) values ($1,$2,$3,$4,$5,$6,$7) returning (id,date,query,status,result,duration,error)"#,
        r#"insert into requests (id,date,query,status,result,duration,error) values ($1,$2,$3,$4,$5,$6,$7)
            returning id as "id!:_",date as "date!:_" ,query as "query!:_",status as "status!:_",result,duration,error"#,
        request.id,
        request.date,
        request.query,
        request.status,
        request.result,
        request.duration,
        request.error,
    )
    .fetch_one(&ctx.db)
    // .execute(&ctx.db)
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

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ApiContext>>,
) -> impl axum::response::IntoResponse {
    info!("Upgrading websocket connection");
    tracing::info!("Upgrading websocket connection");
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<ApiContext>) {
    let (mut sink, stream) = socket.split();
    let mut receiver = state.sender.subscribe();

    // forward messages from the channel to the sink
    tokio::spawn(async move {
        while let Ok(msg) = receiver.recv().await {
            if sink.send(msg.into()).await.is_err() {
                break;
            }
        }
    });

    // read incoming messages
    tokio::spawn(read(stream));
}

async fn read(mut receiver: SplitStream<WebSocket>) {
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(msg) => {
                debug!("Message received: {}", msg);
            }
            Message::Close(_) => {
                debug!("Closing WebSocket connection");
                break;
            }
            _ => {}
        }
    }
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
        });
        // todo: add test for 'service unavailable'
        // let _receiver = state.sender.subscribe();

        // test server
        let router = router().with_state(state);
        let server = TestServer::builder()
            .http_transport()
            .build(router)
            .unwrap();

        let mut websocket = server
            .get_websocket(&"/feasibility/ws")
            .await
            .into_websocket()
            .await;

        // request data
        let query = FeasibilityQuery {
            version: "1".to_string(),
            display: "one".to_string(),
            inclusion_criteria: vec![],
            exclusion_criteria: vec![],
        };

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
        });

        // test server
        let router = router().with_state(state);
        let server = TestServer::new(router).unwrap();

        // request data
        let query = FeasibilityQuery {
            version: "2".to_string(),
            display: "two".to_string(),
            inclusion_criteria: vec![],
            exclusion_criteria: vec![],
        };

        // send request
        let response = server
            .post("/feasibility/request")
            .json(&query.clone())
            .await;

        // assert
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }
}
