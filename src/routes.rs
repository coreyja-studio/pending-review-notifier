use axum::{Router, extract::State, routing::get};
use cja::app_state::AppState as _;
use maud::{DOCTYPE, Markup, html};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(landing))
        .route("/healthz", get(healthz))
}

async fn healthz(State(state): State<AppState>) -> String {
    format!("OK {}", state.version())
}

async fn landing() -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Pending Review Notifier" }
            }
            body {
                h1 { "Pending Review Notifier" }
                p {
                    "GitHub never reminds you about your own unsubmitted pending reviews — \
                    the comments you wrote but never clicked \"Submit\" on, invisible to \
                    everyone but you. Pending Review Notifier watches for them and sends \
                    you a daily digest when one has been sitting longer than your \
                    threshold, so feedback stops silently rotting in draft."
                }
                p {
                    a href="https://github.com/apps/pending-review-notifier" { "Install" }
                    " · "
                    a href="/login" { "Sign in" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use cja::server::cookies::CookieKey;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt as _;

    use super::*;
    use crate::state::AppConfig;

    /// AppState for router tests. The pool is created lazily and never
    /// actually connects — none of the routes under test touch the DB.
    fn test_state() -> AppState {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/prn_test_never_connected")
            .expect("lazy pool creation should not require a running database");

        AppState {
            db,
            cookie_key: CookieKey::generate(),
            config: AppConfig {
                github_client_id: "test-client-id".to_string(),
                github_client_secret: "test-client-secret".to_string(),
                token_enc_key: "test-key".to_string(),
                base_url: "http://localhost:3000".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn healthz_returns_200_with_version() {
        let app = routes().with_state(test_state());

        let response = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    #[tokio::test]
    async fn landing_returns_200() {
        let app = routes().with_state(test_state());

        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
