pub mod oidc;
mod session;
use axum::{Router, http::StatusCode, routing::get};

pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .merge(oidc::router())
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_no_content() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("health request must succeed");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
