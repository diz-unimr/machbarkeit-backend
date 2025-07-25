use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub(crate) struct ApiError(pub anyhow::Error, pub StatusCode);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.1, format!("{}", self.0)).into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into(), StatusCode::INTERNAL_SERVER_ERROR)
    }
}
