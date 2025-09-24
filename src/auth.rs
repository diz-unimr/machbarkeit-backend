use crate::server::ApiContext;
use auth::oauth::{callback, CSRF_STATE_KEY, NEXT_URL_KEY};
use auth::users::{AuthSession, BearerCreds, Credentials};
use axum::extract::{Query, Request, State};
use axum::middleware::Next;
use axum::routing::post;
use axum::{
    debug_handler, http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use axum_login::tower_sessions::Session;
use axum_login::AuthnBackend;
use serde::Deserialize;
use std::sync::Arc;
use urlencoding::Encoded;

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

pub async fn auth_middleware(
    State(state): State<Arc<ApiContext>>,
    auth_session: AuthSession,
    creds: Option<TypedHeader<Authorization<Bearer>>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    match creds.clone() {
        Some(c) => {
            if state.auth.is_some() {
                match auth_session
                    .backend
                    .authenticate(Credentials::Bearer(BearerCreds {
                        token: c.token().to_string(),
                    }))
                    .await
                {
                    Ok(_) => next.run(request).await,
                    Err(e) => (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
                }
            } else {
                next.run(request).await
            }
        }
        None => match auth_session.user {
            None => {
                let login_uri = request.uri().to_string();

                Redirect::temporary(
                    ("/login?next=".to_string() + &*Encoded(login_uri).to_string()).as_str(),
                )
                .into_response()
            }
            Some(_) => next.run(request).await,
        },
    }
}

#[debug_handler]
async fn login(
    auth_session: AuthSession,
    session: Session,
    Query(NextUrl { next }): Query<NextUrl>,
) -> impl IntoResponse {
    // check already logged in
    match auth_session.user {
        Some(_) => StatusCode::OK.into_response(),
        None => {
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
    }
}

#[debug_handler]
async fn logout(
    mut auth_session: AuthSession,
    Query(NextUrl { next }): Query<NextUrl>,
) -> impl IntoResponse {
    match auth_session.logout().await {
        Ok(_) => Redirect::to(next.unwrap_or("/".to_string()).as_str()).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
