use axum::extract::{State, WebSocketUpgrade};
use axum::Router;

use crate::feasibility::api;
use crate::server::ApiContext;
use axum::extract::ws::{Message, WebSocket};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{
    sink::SinkExt,
    stream::{SplitStream, StreamExt},
};
use log::error;
use std::sync::Arc;
use tracing::log::{debug, info};

pub(crate) fn router() -> Router<Arc<ApiContext>> {
    Router::new().route("/feasibility/ws", get(ws_handler))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ApiContext>>,
) -> impl IntoResponse {
    info!("Upgrading websocket connection");
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
    tokio::spawn(ws_read(stream, state));
}

async fn ws_read(mut receiver: SplitStream<WebSocket>, state: Arc<ApiContext>) {
    info!("Reading websocket connection");
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(msg) => {
                debug!("Message received: {}", msg);

                // store result
                if let Err(err) = api::store_result(msg, state.clone()).await {
                    error!("Failed to store feasibility result: {}", err);
                }
            }
            Message::Close(_) => {
                debug!("Closing WebSocket connection");
                break;
            }
            _ => error!("Unexpected message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use chrono::{DateTime, Utc};
    use http::StatusCode;
    use serde_derive::Deserialize;
    use serde_json::json;
    use sqlx::types::JsonValue;
    use sqlx::SqlitePool;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    #[derive(Deserialize)]
    struct Id {
        id: Uuid,
        date: DateTime<Utc>,
    }

    #[sqlx::test]
    async fn websocket_read_test(pool: SqlitePool) {
        let _ = env_logger::try_init();

        let (sender, _) = broadcast::channel(1);
        let state = Arc::new(ApiContext {
            db: pool,
            base_url: "http://localhost".to_string(),
            sender,
        });

        // test server
        let router = router().merge(api::router()).with_state(state);
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
        let response = server.post("/feasibility/request").json(&query).await;

        let accepted = response.json::<Id>();

        // set feasibility result
        let msg = json!({
            "id": accepted.id,
            "status" : "completed",
            "date": accepted.date,
            "query": query,
            "result_code" : 200,
            "result_body" : "42",
            "result_duration" : 600,
        })
        .to_string();

        // send message through websocket
        tokio::spawn(async move { websocket.send_text(&msg).await })
            .await
            .unwrap();

        // check result
        let response = server
            .get(format!("/feasibility/request/{}", accepted.id).as_str())
            .await;

        // assert
        response.assert_status(StatusCode::OK);
        response.assert_text("42");
    }
}
