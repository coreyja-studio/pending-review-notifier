use axum::{
    Form, Router,
    extract::{Path as AxumPath, State},
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
use uuid::Uuid;

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
        .route("/dismiss/{id}", post(dismiss))
        .route("/settings", get(settings).post(update_settings))
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

/// Shared `<head>` for every page. The whole stylesheet is inlined — one
/// hand-written file, no build step, no extra request.
fn page_head(title: &str) -> Markup {
    html! {
        head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            title { (title) }
            style { (PreEscaped(include_str!("style.css"))) }
        }
    }
}

/// Signed-in masthead: wordmark, identity, one nav link, logout.
fn masthead(user: &CurrentUser, on_settings: bool) -> Markup {
    html! {
        header class="masthead" {
            a class="wordmark" href="/dashboard" { "Pending Review Notifier" }
            nav {
                span class="whoami" { (user.github_login) }
                @if on_settings {
                    a href="/dashboard" { "Dashboard" }
                } @else {
                    a href="/settings" { "Settings" }
                }
                form method="post" action="/logout" {
                    input type="hidden" name="csrf" value=(user.csrf_hex());
                    button type="submit" class="btn-bare" { "Log out" }
                }
            }
        }
    }
}

fn page_footer() -> Markup {
    html! {
        footer class="footer" { "No tracking. Disconnect deletes everything." }
    }
}

async fn landing() -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            (page_head("Pending Review Notifier"))
            body {
                div class="wrap" {
                    main {
                        h1 { "Pending Review Notifier" }
                        p class="lede" {
                            "GitHub never reminds you about your own unsubmitted pending reviews — \
                            the comments you wrote but never clicked \"Submit\" on, invisible to \
                            everyone but you. Pending Review Notifier watches for them and sends \
                            you a daily digest when one has been sitting longer than your \
                            threshold, so feedback stops silently rotting in draft."
                        }
                        div class="actions" {
                            a class="btn btn-primary" href="https://github.com/apps/pending-review-notifier" { "Install the GitHub App" }
                            a class="btn" id="login-link" href="/login" { "Sign in" }
                        }
                        p class="fine" { "Free. At most one email a day. Nothing stored you can't delete." }
                    }
                    (page_footer())
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

/// Human-readable age from `last_comment_at` to now (e.g. "3d", "2w", "5h", "12m").
fn format_age(last_comment_at: chrono::DateTime<chrono::Utc>) -> String {
    let elapsed = chrono::Utc::now() - last_comment_at;
    if elapsed.num_days() >= 7 {
        format!("{}w", elapsed.num_days() / 7)
    } else if elapsed.num_days() > 0 {
        format!("{}d", elapsed.num_days())
    } else if elapsed.num_hours() > 0 {
        format!("{}h", elapsed.num_hours())
    } else {
        format!("{}m", elapsed.num_minutes().max(0))
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

    let reviews = sqlx::query!(
        "SELECT id, pr_title, repo_name_with_owner, pr_url, comment_count, last_comment_at, is_backlog
         FROM pending_reviews
         WHERE user_id = $1 AND dismissed_at IS NULL
         ORDER BY last_comment_at DESC",
        user.user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(internal_error)?;

    // Partition into email-eligible (is_backlog = false) and backlog (is_backlog = true).
    let email_eligible: Vec<_> = reviews.iter().filter(|r| !r.is_backlog).collect();
    let backlog: Vec<_> = reviews.iter().filter(|r| r.is_backlog).collect();

    Ok(html! {
        (DOCTYPE)
        html lang="en" {
            (page_head("Dashboard — Pending Review Notifier"))
            body {
                div class="wrap" {
                    (masthead(&user, false))
                    main {
                        @if email_eligible.is_empty() && backlog.is_empty() {
                            p class="empty" { "No pending reviews anywhere. Close the tab." }
                        } @else {
                            section class="group" {
                                header class="group-header" {
                                    span { "Email-eligible" }
                                    span class="count" { (email_eligible.len()) }
                                }
                                @if email_eligible.is_empty() {
                                    p class="empty" { "Nothing newly stale. Good." }
                                } @else {
                                    ul class="review-list" {
                                        @for review in &email_eligible {
                                            li class="review" {
                                                div class="review-main" {
                                                    a class="review-title" href=(format!("{}/files", review.pr_url)) { (review.pr_title) }
                                                    p class="review-meta" {
                                                        (review.repo_name_with_owner)
                                                        " · " (review.comment_count)
                                                        @if review.comment_count == 1 { " comment" } @else { " comments" }
                                                        " · "
                                                        span class="age-hot" { (format_age(review.last_comment_at)) }
                                                        " since last comment"
                                                    }
                                                }
                                                form method="post" action=(format!("/dismiss/{}", review.id)) {
                                                    input type="hidden" name="csrf" value=(user.csrf_hex());
                                                    button type="submit" class="btn btn-dismiss" { "Dismiss" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            section class="group group--backlog" {
                                header class="group-header" {
                                    span { "Backlog — already stale when first seen" }
                                    span class="count" { (backlog.len()) }
                                }
                                @if backlog.is_empty() {
                                    p class="empty" { "Backlog clear." }
                                } @else {
                                    ul class="review-list" {
                                        @for review in &backlog {
                                            li class="review" {
                                                div class="review-main" {
                                                    a class="review-title" href=(format!("{}/files", review.pr_url)) { (review.pr_title) }
                                                    p class="review-meta" {
                                                        (review.repo_name_with_owner)
                                                        " · " (review.comment_count)
                                                        @if review.comment_count == 1 { " comment" } @else { " comments" }
                                                        " · " (format_age(review.last_comment_at))
                                                        " since last comment"
                                                    }
                                                }
                                                form method="post" action=(format!("/dismiss/{}", review.id)) {
                                                    input type="hidden" name="csrf" value=(user.csrf_hex());
                                                    button type="submit" class="btn btn-dismiss" { "Dismiss" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        section class="group" {
                            header class="group-header" {
                                span { "Coverage" }
                            }
                            @if installations.is_empty() {
                                p class="empty" { "No installations yet — install the app to get coverage." }
                            } @else {
                                ul class="coverage-list" {
                                    @for installation in &installations {
                                        li {
                                            (installation.account_login)
                                            " · " (installation.repository_selection) " repositories"
                                        }
                                    }
                                }
                            }
                            p class="fine" { a href=(github::INSTALL_URL) { "Add more repos →" } }
                        }
                    }
                    (page_footer())
                }
            }
        }
    })
}

/// `POST /dismiss/{id}` — set `dismissed_at = now()` on a pending review row.
/// Scoped to the current user; idempotent (`AND dismissed_at IS NULL`).
async fn dismiss(
    State(state): State<AppState>,
    user: CurrentUser,
    AxumPath(review_id): AxumPath<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, Response> {
    if !csrf_matches(&user.csrf_token, form.csrf.as_deref().unwrap_or_default()) {
        return Err(csrf_rejection());
    }
    sqlx::query!(
        "UPDATE pending_reviews SET dismissed_at = now()
         WHERE id = $1 AND user_id = $2 AND dismissed_at IS NULL",
        review_id,
        user.user_id
    )
    .execute(&state.db)
    .await
    .map_err(internal_error)?;
    Ok(Redirect::to("/dashboard"))
}

#[derive(Deserialize)]
struct SettingsForm {
    csrf: Option<String>,
    threshold_hours: i32,
    digest_hour: i32,
    timezone: String,
}

/// `GET /settings` — render a settings form pre-filled with the user's current values.
async fn settings(State(state): State<AppState>, user: CurrentUser) -> Result<Markup, Response> {
    let user_row = sqlx::query!(
        "SELECT threshold_hours, digest_hour, timezone FROM users WHERE user_id = $1",
        user.user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(internal_error)?;

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
    let installations: Vec<SettingsInstallation> = installations
        .into_iter()
        .map(|i| SettingsInstallation {
            account_login: i.account_login,
            repository_selection: i.repository_selection,
        })
        .collect();

    Ok(settings_page(
        &user,
        &user_row.threshold_hours,
        &user_row.digest_hour,
        &user_row.timezone,
        &installations,
        None,
    ))
}

/// Reusable settings page renderer. `error` is an optional inline error message.
fn settings_page(
    user: &CurrentUser,
    threshold_hours: &i32,
    digest_hour: &i32,
    timezone: &str,
    installations: &[SettingsInstallation],
    error: Option<&str>,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            (page_head("Settings — Pending Review Notifier"))
            body {
                div class="wrap" {
                    (masthead(user, true))
                    main {
                        h1 { "Settings" }

                        @if let Some(err) = error {
                            p { strong { (err) } }
                        }

                        form method="post" action="/settings" {
                            input type="hidden" name="csrf" value=(user.csrf_hex());
                            div class="field" {
                                label for="threshold_hours" { "Stale threshold" }
                                input id="threshold_hours" type="number" name="threshold_hours"
                                    min="1" value=(threshold_hours);
                                p class="hint" { "Hours since the last comment before a review counts as stale." }
                            }
                            div class="field" {
                                label for="digest_hour" { "Digest hour" }
                                select id="digest_hour" name="digest_hour" {
                                    @for hour in 0..24 {
                                        option value=(hour) selected[hour == *digest_hour] {
                                            (format!("{hour:02}:00"))
                                        }
                                    }
                                }
                                p class="hint" { "Local hour the daily email goes out." }
                            }
                            div class="field" {
                                label for="timezone" { "Timezone" }
                                select id="timezone" name="timezone" {
                                    @for tz in chrono_tz::TZ_VARIANTS {
                                        option value=(tz.name()) selected[tz.name() == timezone] {
                                            (tz.name())
                                        }
                                    }
                                }
                            }
                            button type="submit" class="btn btn-primary" { "Save" }
                        }

                        section class="group" {
                            header class="group-header" {
                                span { "Coverage" }
                            }
                            @if installations.is_empty() {
                                p class="empty" { "No installations yet — install the app to get coverage." }
                            } @else {
                                ul class="coverage-list" {
                                    @for installation in installations {
                                        li {
                                            (installation.account_login)
                                            " · " (installation.repository_selection) " repositories"
                                        }
                                    }
                                }
                            }
                            p class="fine" { a href=(github::INSTALL_URL) { "Add more repos →" } }
                        }

                        section class="danger" {
                            h2 { "Disconnect" }
                            p {
                                "Revokes the GitHub grant and deletes your account, pending \
                                reviews, and sessions. Cannot be undone."
                            }
                            form method="post" action="/disconnect"
                                onsubmit="return confirm('Disconnect from GitHub and delete all your data? This cannot be undone.')" {
                                input type="hidden" name="csrf" value=(user.csrf_hex());
                                button type="submit" class="btn btn-danger" { "Disconnect from GitHub" }
                            }
                        }
                    }
                    (page_footer())
                }
            }
        }
    }
}

/// Row type for the installations query in settings.
struct SettingsInstallation {
    account_login: String,
    repository_selection: String,
}

/// `POST /settings` — validate and update the user's settings.
async fn update_settings(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<SettingsForm>,
) -> Result<Response, Response> {
    if !csrf_matches(&user.csrf_token, form.csrf.as_deref().unwrap_or_default()) {
        return Err(csrf_rejection());
    }

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

    let installations: Vec<SettingsInstallation> = installations
        .into_iter()
        .map(|i| SettingsInstallation {
            account_login: i.account_login,
            repository_selection: i.repository_selection,
        })
        .collect();

    if form.threshold_hours < 1 {
        return Ok(settings_page(
            &user,
            &form.threshold_hours,
            &form.digest_hour,
            &form.timezone,
            &installations,
            Some("Threshold must be at least 1 hour."),
        )
        .into_response());
    }

    if !(0..=23).contains(&form.digest_hour) {
        return Ok(settings_page(
            &user,
            &form.threshold_hours,
            &form.digest_hour,
            &form.timezone,
            &installations,
            Some("Digest hour must be between 0 and 23."),
        )
        .into_response());
    }

    if form.timezone.parse::<chrono_tz::Tz>().is_err() {
        return Ok(settings_page(
            &user,
            &form.threshold_hours,
            &form.digest_hour,
            &form.timezone,
            &installations,
            Some(&format!("Unknown timezone: {}", form.timezone)),
        )
        .into_response());
    }

    sqlx::query!(
        "UPDATE users SET threshold_hours = $1, digest_hour = $2, timezone = $3 WHERE user_id = $4",
        form.threshold_hours,
        form.digest_hour,
        form.timezone,
        user.user_id
    )
    .execute(&state.db)
    .await
    .map_err(internal_error)?;

    Ok(Redirect::to("/settings").into_response())
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
        http::{Request, StatusCode, header},
    };
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use tower::ServiceExt as _;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    use super::*;
    use crate::state::test_support::{lazy_test_state, test_config, test_state};

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

    // --- Helpers for authed route tests ---

    async fn mock_backed_state(db: PgPool) -> (AppState, MockServer) {
        let mock = MockServer::start().await;
        let mut config = test_config();
        config.github_oauth_base = mock.uri();
        config.github_api_base = mock.uri();
        (test_state(db, config), mock)
    }

    fn cookie_header(response: &axum::response::Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .filter(|pair| {
                pair.split_once('=')
                    .is_some_and(|(_, value)| !value.is_empty())
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn location(response: &axum::response::Response) -> &str {
        response
            .headers()
            .get(header::LOCATION)
            .expect("expected a Location header")
            .to_str()
            .unwrap()
    }

    async fn do_login(app: &Router, uri: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let authorize_url = url::Url::parse(location(&response)).unwrap();
        let state = authorize_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .expect("authorize URL must carry a state param")
            .1
            .to_string();

        (state, cookie_header(&response))
    }

    async fn do_callback(
        app: &Router,
        state_param: &str,
        cookies: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::get(format!("/callback?code=test-code&state={state_param}"))
                    .header(header::COOKIE, cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn full_sign_in(app: &Router, _db: &PgPool) -> String {
        let (oauth_state, cookies) = do_login(app, "/login").await;
        let response = do_callback(app, &oauth_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        cookie_header(&response)
    }

    fn post_form(uri: &str, cookies: &str, body: String) -> Request<Body> {
        Request::post(uri)
            .header(header::COOKIE, cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    async fn csrf_hex(db: &PgPool) -> String {
        let token = sqlx::query_scalar!("SELECT csrf_token FROM user_sessions")
            .fetch_one(db)
            .await
            .unwrap();
        hex::encode(token)
    }

    async fn mount_token_exchange(mock: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("code=test-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_test_access",
                "refresh_token": "ghr_test_refresh",
                "expires_in": 28800,
                "refresh_token_expires_in": 15_897_600,
                "token_type": "bearer",
                "scope": ""
            })))
            .mount(mock)
            .await;
    }

    async fn mount_user_endpoints(mock: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "viewer": { "login": "coreyja", "databaseId": 12345 } }
            })))
            .mount(mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "email": "corey@example.com", "primary": true, "verified": true }
            ])))
            .mount(mock)
            .await;
    }

    async fn mount_installations(mock: &MockServer, installations: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": installations.as_array().map_or(0, Vec::len),
                "installations": installations
            })))
            .mount(mock)
            .await;
    }

    /// Insert a pending review row directly for testing.
    #[allow(clippy::too_many_arguments)]
    async fn insert_review(
        db: &PgPool,
        user_id: Uuid,
        review_id: &str,
        pr_title: &str,
        repo: &str,
        comment_count: i32,
        last_comment_at: chrono::DateTime<chrono::Utc>,
        is_backlog: bool,
    ) -> Uuid {
        let row = sqlx::query!(
            "INSERT INTO pending_reviews (
                review_id, user_id, pr_url, pr_title, repo_name_with_owner,
                comment_count, last_comment_at, last_seen_at, is_backlog
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id",
            review_id,
            user_id,
            format!("https://github.com/{}/pull/1", repo),
            pr_title,
            repo,
            comment_count,
            last_comment_at,
            Utc::now(),
            is_backlog,
        )
        .fetch_one(db)
        .await
        .unwrap();
        row.id
    }

    // --- Dashboard tests ---

    #[sqlx::test]
    async fn dashboard_shows_pending_reviews(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let user_id: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        insert_review(
            &db,
            user_id,
            "R1",
            "Fix the bug",
            "o/r",
            2,
            Utc::now() - Duration::hours(5),
            false,
        )
        .await;
        insert_review(
            &db,
            user_id,
            "R2",
            "Backlog item",
            "o/r2",
            1,
            Utc::now() - Duration::hours(10),
            true,
        )
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/dashboard")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        // Email-eligible review is present
        assert!(body.contains("Fix the bug"));
        assert!(body.contains("o/r"));
        // Backlog review is present
        assert!(body.contains("Backlog item"));
        assert!(body.contains("o/r2"));
        // Links point to /files
        assert!(body.contains("/files"));
        // Dismiss buttons present
        assert!(body.contains("/dismiss/"));
    }

    #[sqlx::test]
    async fn dashboard_hides_dismissed_reviews(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let user_id: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        let _active_id = insert_review(
            &db,
            user_id,
            "R1",
            "Active PR",
            "o/r",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;
        insert_review(
            &db,
            user_id,
            "R2",
            "Dismissed PR",
            "o/r2",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;

        // Dismiss the second one
        sqlx::query!("UPDATE pending_reviews SET dismissed_at = now() WHERE review_id = 'R2'")
            .execute(&db)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::get("/dashboard")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("Active PR"));
        assert!(!body.contains("Dismissed PR"));
    }

    #[sqlx::test]
    async fn dashboard_escapes_xss_in_titles(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let user_id: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        insert_review(
            &db,
            user_id,
            "RX",
            "<script>alert('xss')</script>",
            "o/r",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/dashboard")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        // maud auto-escapes: the script tag must not appear as raw HTML
        assert!(!body.contains("<script>alert('xss')</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    // --- Dismiss tests ---

    #[sqlx::test]
    async fn dismiss_requires_csrf(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let user_id: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        let review_id = insert_review(
            &db,
            user_id,
            "R1",
            "Test PR",
            "o/r",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;

        // No CSRF token
        let response = app
            .clone()
            .oneshot(post_form(
                &format!("/dismiss/{}", review_id),
                &session_cookies,
                String::new(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Wrong CSRF token
        let response = app
            .clone()
            .oneshot(post_form(
                &format!("/dismiss/{}", review_id),
                &session_cookies,
                format!("csrf={}", "0".repeat(64)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Row untouched
        let dismissed: Option<chrono::DateTime<Utc>> = sqlx::query_scalar!(
            "SELECT dismissed_at FROM pending_reviews WHERE id = $1",
            review_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(dismissed.is_none());
    }

    #[sqlx::test]
    async fn dismiss_with_valid_csrf_sets_dismissed_at(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;
        let user_id: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        let review_id = insert_review(
            &db,
            user_id,
            "R1",
            "Test PR",
            "o/r",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;

        let response = app
            .clone()
            .oneshot(post_form(
                &format!("/dismiss/{}", review_id),
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/dashboard");

        let dismissed: Option<chrono::DateTime<Utc>> = sqlx::query_scalar!(
            "SELECT dismissed_at FROM pending_reviews WHERE id = $1",
            review_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(dismissed.is_some());
    }

    #[sqlx::test]
    async fn dismiss_is_user_scoped(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;

        // User A (signed in) has a review. User B has a separate review.
        let _user_a: Uuid = sqlx::query_scalar!("SELECT user_id FROM users")
            .fetch_one(&db)
            .await
            .unwrap();

        let user_b = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email
            )
            VALUES ($1, 'other', 99999, $2, $3, $4, 'other@example.com')",
            user_b,
            state.crypto.encrypt("tok", user_b.as_bytes()).unwrap(),
            state.crypto.encrypt("ref", user_b.as_bytes()).unwrap(),
            Utc::now() + Duration::days(30),
        )
        .execute(&db)
        .await
        .unwrap();

        let review_b_id = insert_review(
            &db,
            user_b,
            "RB",
            "Other user PR",
            "o/r3",
            1,
            Utc::now() - Duration::hours(3),
            false,
        )
        .await;

        // User A tries to dismiss user B's review
        let response = app
            .clone()
            .oneshot(post_form(
                &format!("/dismiss/{}", review_b_id),
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // User B's row is untouched
        let dismissed: Option<chrono::DateTime<Utc>> = sqlx::query_scalar!(
            "SELECT dismissed_at FROM pending_reviews WHERE id = $1",
            review_b_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(dismissed.is_none());
    }

    // --- Settings tests ---

    #[sqlx::test]
    async fn settings_shows_current_values(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/settings")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        // Default values
        assert!(body.contains("threshold_hours"));
        assert!(body.contains("digest_hour"));
        assert!(body.contains("timezone"));
        assert!(body.contains("UTC")); // default timezone
    }

    #[sqlx::test]
    async fn settings_update_changes_values(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/settings",
                &session_cookies,
                format!("csrf={csrf}&threshold_hours=8&digest_hour=14&timezone=America/New_York"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/settings");

        let user = sqlx::query!("SELECT threshold_hours, digest_hour, timezone FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.threshold_hours, 8);
        assert_eq!(user.digest_hour, 14);
        assert_eq!(user.timezone, "America/New_York");
    }

    #[sqlx::test]
    async fn settings_rejects_invalid_timezone(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/settings",
                &session_cookies,
                format!("csrf={csrf}&threshold_hours=4&digest_hour=9&timezone=Not/A/Zone"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Unknown timezone"));

        // Values unchanged
        let user = sqlx::query!("SELECT timezone FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.timezone, "UTC");
    }

    #[sqlx::test]
    async fn settings_rejects_invalid_threshold(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/settings",
                &session_cookies,
                format!("csrf={csrf}&threshold_hours=0&digest_hour=9&timezone=UTC"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Threshold must be at least 1"));

        // Values unchanged
        let user = sqlx::query!("SELECT threshold_hours FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.threshold_hours, 4); // default
    }

    #[sqlx::test]
    async fn settings_rejects_invalid_digest_hour(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/settings",
                &session_cookies,
                format!("csrf={csrf}&threshold_hours=4&digest_hour=25&timezone=UTC"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Digest hour must be between 0 and 23"));

        let user = sqlx::query!("SELECT digest_hour FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.digest_hour, 9); // default
    }

    #[sqlx::test]
    async fn settings_requires_csrf(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = full_sign_in(&app, &db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/settings",
                &session_cookies,
                "threshold_hours=8&digest_hour=14&timezone=UTC".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Values unchanged
        let user = sqlx::query!("SELECT threshold_hours FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.threshold_hours, 4);
    }
}
