use crate::server::ApiContext;
use auth::oauth::{callback, CSRF_STATE_KEY, NEXT_URL_KEY};
use auth::users::AuthSession;
use axum::extract::Query;
use axum::routing::post;
use axum::{
    debug_handler, http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_login::tower_sessions::Session;
use serde::Deserialize;
use std::sync::Arc;

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn router() -> Router<Arc<ApiContext>> {
    Router::new()
        .route("/login", post(login))
        .route("/login", get(login))
        .route("/logout", get(logout))
        .route("/oauth/callback", get(callback))
}

#[debug_handler]
async fn login(
    auth_session: AuthSession,
    session: Session,
    Query(NextUrl { next }): Query<NextUrl>,
) -> impl IntoResponse {
    let (auth_url, csrf_state) = auth_session.backend.authorize_url();

    session
        .insert(CSRF_STATE_KEY, csrf_state.secret())
        .await
        .expect("Serialization should not fail.");

    session
        .insert(NEXT_URL_KEY, next)
        .await
        .expect("Serialization should not fail.");

    Redirect::to(auth_url.as_str()).into_response()
}

#[debug_handler]
async fn logout(
    mut auth_session: AuthSession,
    Query(NextUrl { next }): Query<NextUrl>,
) -> impl IntoResponse {
    match auth_session.logout().await {
        // Ok(_) => Redirect::to("/login").into_response(),
        Ok(_) => Redirect::to(next.unwrap_or("/".to_string()).as_str()).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
