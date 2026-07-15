use axum::{
    Form, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Redirect, Response},
    routing::{get, post},
};
use cja::{
    app_state::AppState as _,
    server::{
        cookies::{Cookie, CookieJar},
        session::Session,
    },
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use crate::{
    github,
    session::{CurrentUser, PrnSession, csrf_matches},
    state::AppState,
};

/// Hidden-input payload carried by every state-changing form.
#[derive(Deserialize)]
struct CsrfForm {
    csrf: Option<String>,
}

fn csrf_rejection() -> Response {
    (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(landing))
        .route("/healthz", get(healthz))
        .route("/login", get(github::oauth::login))
        .route("/callback", get(github::oauth::callback))
        .route("/logout", post(logout))
        .route("/disconnect", post(disconnect))
        .route("/dashboard", get(dashboard))
}

/// Log the error and return an opaque 500. Never include token material in
/// errors passed here (sqlx/reqwest errors don't carry bind values or bodies).
fn internal_error<E: std::fmt::Debug>(err: E) -> Response {
    tracing::error!(?err, "Request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
                    a id="login-link" href="/login" { "Sign in" }
                }
                // Capture the browser timezone at signup: rewrite the sign-in
                // link so /login can stash the tz in the OAuth state cookie.
                script {
                    (PreEscaped(r#"
                    document.addEventListener('DOMContentLoaded', function () {
                        try {
                            var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                            var link = document.getElementById('login-link');
                            if (tz && link) {
                                link.href = '/login?tz=' + encodeURIComponent(tz);
                            }
                        } catch (e) { /* default of UTC applies */ }
                    });
                    "#))
                }
            }
        }
    }
}

async fn dashboard(State(state): State<AppState>, user: CurrentUser) -> Result<Markup, Response> {
    let installations = sqlx::query!(
        "SELECT i.account_login, i.repository_selection
         FROM installations i
         JOIN user_installations ui ON ui.installation_id = i.installation_id
         WHERE ui.user_id = $1
         ORDER BY i.account_login",
        user.user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(internal_error)?;

    Ok(html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Dashboard — Pending Review Notifier" }
            }
            body {
                h1 { "Dashboard" }
                p { "Signed in as " strong { (user.github_login) } "." }

                h2 { "Covered installations" }
                @if installations.is_empty() {
                    p { "No installations yet — install the app to get coverage." }
                } @else {
                    ul {
                        @for installation in &installations {
                            li {
                                (installation.account_login)
                                " (" (installation.repository_selection) " repositories)"
                            }
                        }
                    }
                }
                p { a href=(github::INSTALL_URL) { "Add more repos" } }

                form method="post" action="/logout" {
                    input type="hidden" name="csrf" value=(user.csrf_hex());
                    button type="submit" { "Log out" }
                }
                form method="post" action="/disconnect"
                    onsubmit="return confirm('Disconnect from GitHub and delete all your data? This cannot be undone.')" {
                    input type="hidden" name="csrf" value=(user.csrf_hex());
                    button type="submit" { "Disconnect" }
                }
            }
        }
    })
}

/// `POST /logout` — detach the user from the session (the anonymous session
/// and its cookie live on). CSRF-guarded when a user is attached.
async fn logout(
    State(state): State<AppState>,
    Session(session): Session<PrnSession>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, Response> {
    if session.user_id.is_some() {
        let expected = session.csrf_token.as_deref().unwrap_or_default();
        if !csrf_matches(expected, form.csrf.as_deref().unwrap_or_default()) {
            return Err(csrf_rejection());
        }
        session
            .clear_user(&state.db)
            .await
            .map_err(internal_error)?;
    }
    Ok(Redirect::to("/"))
}

/// `POST /disconnect` — revoke the grant at GitHub, delete the user (cascades
/// pending reviews, installation links, and session mappings), destroy the
/// session. CSRF-guarded.
async fn disconnect(
    State(state): State<AppState>,
    user: CurrentUser,
    jar: CookieJar<AppState>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, Response> {
    if !csrf_matches(&user.csrf_token, form.csrf.as_deref().unwrap_or_default()) {
        return Err(csrf_rejection());
    }

    // Revoke with a *fresh* access token where possible — GitHub may not
    // accept an expired one, and a dangling grant keeps the ~6-month refresh
    // token alive on their side. If the refresh fails, still try with the
    // stored token. Either way, revocation is best-effort: local deletion
    // must never be blockable by GitHub flakiness (404/422 already count as
    // success inside revoke_grant).
    let access_token = match github::oauth::ensure_fresh_token(&state, user.user_id).await {
        Ok(token) => Some(token),
        Err(err) => {
            tracing::warn!(
                ?err,
                "Refresh before revocation failed; falling back to the stored token"
            );
            let row = sqlx::query!(
                "SELECT access_token_enc FROM users WHERE user_id = $1",
                user.user_id
            )
            .fetch_one(&state.db)
            .await
            .map_err(internal_error)?;
            match state
                .crypto
                .decrypt(&row.access_token_enc, user.user_id.as_bytes())
            {
                Ok(token) => Some(token),
                Err(err) => {
                    tracing::error!(?err, "Could not decrypt the stored token for revocation");
                    None
                }
            }
        }
    };

    match access_token {
        Some(access_token) => {
            if let Err(err) = github::revoke_grant(&state, &access_token).await {
                tracing::error!(?err, "Grant revocation failed; deleting local data anyway");
            }
        }
        None => {
            tracing::error!("No usable access token for revocation; deleting local data anyway");
        }
    }

    sqlx::query!("DELETE FROM users WHERE user_id = $1", user.user_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    user.session
        .destroy(&state.db)
        .await
        .map_err(internal_error)?;
    jar.remove(Cookie::build(("session_id", "")).path("/").build());

    Ok(Redirect::to("/"))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::state::test_support::lazy_test_state;

    fn test_app(state: &AppState) -> Router {
        routes()
            .with_state(state.clone())
            .layer(tower_cookies::CookieManagerLayer::new())
    }

    #[tokio::test]
    async fn healthz_returns_200_with_version() {
        let app = test_app(&lazy_test_state());

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
    async fn landing_returns_200_and_captures_tz() {
        let app = test_app(&lazy_test_state());

        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("login-link"));
        assert!(body.contains("Intl.DateTimeFormat().resolvedOptions().timeZone"));
    }
}
