//! GitHub OAuth web flow (user-to-server): /login, /callback, and the
//! token refresh helper used by sync jobs.
//!
//! Security invariants (see the PR checklist):
//! - The state cookie is HttpOnly + Secure + SameSite=Lax, Max-Age 600,
//!   stored in cja's *private* (encrypted) cookie jar, and cleared on use;
//!   the state comparison is constant-time.
//! - Tokens are never logged, only stored encrypted, and each ciphertext is
//!   AAD-bound to its owning user_id.
//! - Refresh tokens rotate: refreshes for a user are serialized with a row
//!   lock, and the new pair is persisted in a single UPDATE *before* the new
//!   access token is returned to the caller.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Redirect, Response},
};
use chrono::Utc;
use cja::jobs::Job as _;
use cja::server::{
    cookies::{Cookie, CookieJar, SameSite},
    session::AppSession as _,
};
use color_eyre::eyre::eyre;
use rand::RngCore as _;
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::{github, session::PrnSession, state::AppState};

/// Name of the (encrypted) cookie carrying the OAuth state.
const STATE_COOKIE: &str = "oauth_state";

/// `GET /login` — set the state cookie and bounce to GitHub's authorize URL.
pub async fn login(State(state): State<AppState>, jar: CookieJar<AppState>) -> Response {
    // 32 hex chars = 128 bits of CSRF entropy.
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let oauth_state = hex::encode(bytes);

    let cookie = Cookie::build((STATE_COOKIE, oauth_state.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::minutes(10))
        .build();
    jar.add(cookie);

    let authorize_url = url::Url::parse_with_params(
        &format!(
            "{}/login/oauth/authorize",
            state.config.github_oauth_base.trim_end_matches('/')
        ),
        &[
            ("client_id", state.config.github_client_id.as_str()),
            (
                "redirect_uri",
                &format!("{}/callback", state.config.base_url.trim_end_matches('/')),
            ),
            ("state", &oauth_state),
        ],
    );

    match authorize_url {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(err) => {
            tracing::error!(?err, "Failed to build GitHub authorize URL");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    // GitHub also sends `installation_id` and `setup_action=install` when the
    // callback is triggered by an app install ("Request user authorization
    // during installation"). Both are informational only — we learn the
    // installations from GET /user/installations either way.
}

/// `GET /callback` — verify state, exchange the code, upsert the user +
/// installations, start a session, and route to install page or dashboard.
pub async fn callback(
    State(app_state): State<AppState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar<AppState>,
) -> Response {
    let stored = jar.get(STATE_COOKIE);
    // The state is single-use: clear the cookie no matter what happens next.
    jar.remove(Cookie::build((STATE_COOKIE, "")).path("/").build());

    // NB: the rejection body must not echo the expected state.
    let Some(stored) = stored else {
        return (StatusCode::FORBIDDEN, "Missing or expired OAuth state").into_response();
    };
    let expected_state = stored.value();

    let state_matches = params
        .state
        .as_deref()
        .is_some_and(|provided| bool::from(provided.as_bytes().ct_eq(expected_state.as_bytes())));
    if !state_matches {
        return (StatusCode::FORBIDDEN, "OAuth state mismatch").into_response();
    }

    let Some(code) = params.code.as_deref() else {
        // e.g. the user cancelled the authorization prompt.
        return (StatusCode::BAD_REQUEST, "Missing authorization code").into_response();
    };

    match signed_in_response(&app_state, code, &jar).await {
        Ok(response) => response,
        Err(err) => {
            // eyre reports here never contain token values.
            tracing::error!(?err, "OAuth callback failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The post-state-verification half of the callback.
async fn signed_in_response(
    state: &AppState,
    code: &str,
    jar: &CookieJar<AppState>,
) -> cja::Result<Response> {
    let tokens = exchange_code(state, code).await?;

    let viewer = github::fetch_viewer(state, &tokens.access_token).await?;
    let email = github::fetch_primary_email(state, &tokens.access_token).await?;

    let token_expires_at = Utc::now() + chrono::Duration::seconds(tokens.expires_in);

    // Upsert by the rename-stable github_user_id. Token ciphertexts are
    // AAD-bound to the user_id, which for an existing user must be the row's
    // id — so lock the row first, then encrypt under the definitive id.
    // (Two truly concurrent FIRST sign-ins of the same account can race to a
    // unique violation; that 500 is a retry-once curiosity, not a lockout.)
    //
    // A re-login clears needs_reauth (the user just proved they can auth),
    // but leaves a deliberate 'paused' alone.
    let mut tx = state.db.begin().await?;
    let existing_user_id = sqlx::query_scalar!(
        "SELECT user_id FROM users WHERE github_user_id = $1 FOR UPDATE",
        viewer.database_id
    )
    .fetch_optional(&mut *tx)
    .await?;

    let user_id = existing_user_id.unwrap_or_else(Uuid::new_v4);
    let access_token_enc = state
        .crypto
        .encrypt(&tokens.access_token, user_id.as_bytes())?;
    let refresh_token_enc = state
        .crypto
        .encrypt(&tokens.refresh_token, user_id.as_bytes())?;

    if existing_user_id.is_some() {
        sqlx::query!(
            r#"
            UPDATE users SET
                github_login = $1,
                email = $2,
                access_token_enc = $3,
                refresh_token_enc = $4,
                token_expires_at = $5,
                status = CASE
                    WHEN status = 'needs_reauth' THEN 'active'
                    ELSE status
                END
            WHERE user_id = $6
            "#,
            viewer.login,
            email,
            access_token_enc,
            refresh_token_enc,
            token_expires_at,
            user_id,
        )
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query!(
            r#"
            INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            user_id,
            viewer.login,
            viewer.database_id,
            access_token_enc,
            refresh_token_enc,
            token_expires_at,
            email,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // Installations are shared entities (org mates see the same ones), so
    // the row itself is upserted separately from this user's link to it.
    let installations = github::fetch_user_installations(state, &tokens.access_token).await?;
    for installation in &installations {
        sqlx::query!(
            r#"
            INSERT INTO installations (
                installation_id, account_login, repository_selection, last_seen_at
            )
            VALUES ($1, $2, $3, now())
            ON CONFLICT (installation_id) DO UPDATE SET
                account_login = EXCLUDED.account_login,
                repository_selection = EXCLUDED.repository_selection,
                last_seen_at = now()
            "#,
            installation.id,
            installation.account_login,
            installation.repository_selection,
        )
        .execute(&state.db)
        .await?;

        sqlx::query!(
            "INSERT INTO user_installations (user_id, installation_id, last_seen_at)
             VALUES ($1, $2, now())
             ON CONFLICT (user_id, installation_id) DO UPDATE SET last_seen_at = now()",
            user_id,
            installation.id,
        )
        .execute(&state.db)
        .await?;
    }

    // Fresh session per sign-in. cja's extractor would save this cookie
    // without SameSite, so we set it ourselves (Lax) — the extractor only
    // ever writes cookies for the anonymous sessions it auto-creates.
    let session = PrnSession::create(&state.db).await?;
    session.set_user(&state.db, user_id).await?;
    let session_cookie = Cookie::build(("session_id", session.session_id().to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    jar.add(session_cookie);

    // Kick off an initial pending-review sync so the dashboard has data on the
    // user's first visit. Best-effort: a queue hiccup must not fail the login —
    // the SyncSweep cron will pick the user up within 30 min regardless.
    if let Err(error) = (crate::jobs::SyncUser { user_id })
        .enqueue(state.clone(), "signup".to_string(), None)
        .await
    {
        tracing::error!(?error, %user_id, "failed to enqueue initial SyncUser on signup");
    }

    let destination = if installations.is_empty() {
        github::INSTALL_URL
    } else {
        "/dashboard"
    };
    Ok(Redirect::to(destination).into_response())
}

/// A fresh access/refresh token pair from GitHub.
///
/// Deliberately no `Debug` derive — this holds live tokens.
struct TokenPair {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

enum TokenRequestError {
    /// GitHub definitively said no: an OAuth error payload (HTTP 200 +
    /// `error` field) or a 4xx status. Safe to treat as "this grant is dead".
    Rejected(color_eyre::Report),
    /// No usable answer: network failure, deserialization failure, or a 5xx
    /// (GitHub being down must never mark users needs_reauth).
    Transport(color_eyre::Report),
}

/// POST to the token endpoint (both the code exchange and the refresh grant).
async fn token_request(
    state: &AppState,
    form: &[(&str, &str)],
) -> Result<TokenPair, TokenRequestError> {
    // GitHub's OAuth token endpoint reports errors (e.g. bad_verification_code,
    // bad_refresh_token) as HTTP 200 with an `error` JSON field; Accept:
    // application/json opts into JSON instead of form-encoded bodies.
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        refresh_token: Option<String>,
        expires_in: Option<i64>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let response = state
        .http
        .post(format!(
            "{}/login/oauth/access_token",
            state.config.github_oauth_base.trim_end_matches('/')
        ))
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(|err| TokenRequestError::Transport(err.into()))?;

    let status = response.status();
    if status.is_server_error() {
        return Err(TokenRequestError::Transport(eyre!(
            "token endpoint returned HTTP {status}"
        )));
    }
    if !status.is_success() {
        return Err(TokenRequestError::Rejected(eyre!(
            "token endpoint returned HTTP {status}"
        )));
    }

    let body: TokenResponse = response
        .json()
        .await
        .map_err(|err| TokenRequestError::Transport(err.into()))?;

    if let Some(error) = body.error {
        let description = body.error_description.unwrap_or_default();
        return Err(TokenRequestError::Rejected(eyre!(
            "token endpoint error: {error} {description}"
        )));
    }

    match (body.access_token, body.refresh_token, body.expires_in) {
        (Some(access_token), Some(refresh_token), Some(expires_in)) => Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in,
        }),
        _ => Err(TokenRequestError::Rejected(eyre!(
            "token endpoint response is missing token fields"
        ))),
    }
}

async fn exchange_code(state: &AppState, code: &str) -> cja::Result<TokenPair> {
    let redirect_uri = format!("{}/callback", state.config.base_url.trim_end_matches('/'));
    let form = [
        ("client_id", state.config.github_client_id.as_str()),
        ("client_secret", state.config.github_client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    token_request(state, &form).await.map_err(|err| match err {
        TokenRequestError::Rejected(report) | TokenRequestError::Transport(report) => {
            report.wrap_err("authorization code exchange failed")
        }
    })
}

/// Return a valid access token for the user, refreshing (and rotating the
/// stored pair) if it expires within 5 minutes.
///
/// Concurrency: the user row is locked (`FOR UPDATE`) for the duration, so
/// two concurrent callers can't both spend the single-use refresh token —
/// the second blocks, then sees the already-rotated fresh pair and returns
/// it without another HTTP call.
///
/// On a definitive refresh rejection (e.g. `bad_refresh_token`, 4xx) the
/// user is marked `needs_reauth` and an error is returned. Transport
/// failures and 5xx return an error without changing the user's status, so
/// a GitHub blip doesn't force everyone back through OAuth.
///
/// Used by /disconnect today; the sync jobs in the next PR are the main caller.
pub async fn ensure_fresh_token(state: &AppState, user_id: Uuid) -> cja::Result<String> {
    let mut tx = state.db.begin().await?;

    let row = sqlx::query!(
        "SELECT access_token_enc, refresh_token_enc, token_expires_at
         FROM users WHERE user_id = $1
         FOR UPDATE",
        user_id
    )
    .fetch_one(&mut *tx)
    .await?;

    // This read happened under the lock: if a concurrent caller refreshed
    // while we waited for it, the expiry is already fresh and we're done.
    if row.token_expires_at > Utc::now() + chrono::Duration::minutes(5) {
        tx.commit().await?;
        return state
            .crypto
            .decrypt(&row.access_token_enc, user_id.as_bytes());
    }

    let refresh_token = state
        .crypto
        .decrypt(&row.refresh_token_enc, user_id.as_bytes())?;
    let form = [
        ("client_id", state.config.github_client_id.as_str()),
        ("client_secret", state.config.github_client_secret.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
    ];

    // The HTTP call deliberately happens while holding the row lock — that
    // is what serializes concurrent refreshes (GitHub consumes the refresh
    // token on first use).
    match token_request(state, &form).await {
        Ok(pair) => {
            let access_token_enc = state
                .crypto
                .encrypt(&pair.access_token, user_id.as_bytes())?;
            let refresh_token_enc = state
                .crypto
                .encrypt(&pair.refresh_token, user_id.as_bytes())?;
            let token_expires_at = Utc::now() + chrono::Duration::seconds(pair.expires_in);

            // Refresh tokens rotate: persist BOTH new tokens in one UPDATE,
            // and do it before handing the new access token to the caller —
            // if we die after this statement nothing is lost, whereas using
            // the token first and persisting later could strand the new
            // refresh token and lock the user out. A successful refresh also
            // self-heals a false needs_reauth (paused stays paused).
            sqlx::query!(
                "UPDATE users
                 SET access_token_enc = $1, refresh_token_enc = $2, token_expires_at = $3,
                     status = CASE WHEN status = 'paused' THEN 'paused' ELSE 'active' END
                 WHERE user_id = $4",
                access_token_enc,
                refresh_token_enc,
                token_expires_at,
                user_id
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            Ok(pair.access_token)
        }
        Err(TokenRequestError::Rejected(report)) => {
            sqlx::query!(
                "UPDATE users SET status = 'needs_reauth' WHERE user_id = $1",
                user_id
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Err(report.wrap_err("GitHub rejected the refresh token; user marked needs_reauth"))
        }
        Err(TokenRequestError::Transport(report)) => {
            // Dropping the transaction rolls it back; status is untouched.
            Err(report.wrap_err("token refresh request failed (transient; status unchanged)"))
        }
    }
}

/// These tests need a Postgres server: `#[sqlx::test]` creates a throwaway
/// database per test from `DATABASE_URL` and runs ./migrations in it. CI's
/// postgres service provides this; locally, point DATABASE_URL at any dev DB
/// (e.g. `postgres:///prn_auth_test`).
#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use chrono::{DateTime, Utc};
    use sqlx::PgPool;
    use tower::ServiceExt as _;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, header_exists, method, path},
    };

    use super::*;
    use crate::state::test_support::{lazy_test_state, test_config, test_state};

    fn test_app(state: &AppState) -> Router {
        crate::routes::routes()
            .with_state(state.clone())
            .layer(tower_cookies::CookieManagerLayer::new())
    }

    async fn mock_backed_state(db: PgPool) -> (AppState, MockServer) {
        let mock = MockServer::start().await;
        let mut config = test_config();
        config.github_oauth_base = mock.uri();
        config.github_api_base = mock.uri();
        (test_state(db, config), mock)
    }

    /// Collapse a response's Set-Cookie headers into a Cookie request header,
    /// honouring removals (empty values) the way a browser would.
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

    /// GET /login and return (state param, cookies to send back).
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

    /// Sign in through the full login+callback flow; returns the session
    /// cookie header for subsequent requests.
    async fn sign_in(app: &Router) -> String {
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

    /// The one signed-in session's CSRF token, as the forms would render it.
    async fn csrf_hex(db: &PgPool) -> String {
        let token = sqlx::query_scalar!("SELECT csrf_token FROM user_sessions")
            .fetch_one(db)
            .await
            .unwrap();
        hex::encode(token)
    }

    /// Pull the CSRF hidden-input value out of rendered dashboard HTML.
    fn extract_csrf(body: &str) -> String {
        let marker = "name=\"csrf\" value=\"";
        let start = body.find(marker).expect("a csrf hidden input") + marker.len();
        let end = start + body[start..].find('"').unwrap();
        body[start..end].to_string()
    }

    fn mount_token_exchange(mock: &MockServer) -> impl std::future::Future<Output = ()> + '_ {
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
    }

    async fn mount_user_endpoints(mock: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header_exists("user-agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "viewer": { "login": "coreyja", "databaseId": 12345 } }
            })))
            .mount(mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "email": "spare@example.com", "primary": false, "verified": true },
                { "email": "corey@example.com", "primary": true, "verified": true }
            ])))
            .mount(mock)
            .await;
    }

    fn mount_installations(
        mock: &MockServer,
        installations: serde_json::Value,
    ) -> impl std::future::Future<Output = ()> + '_ {
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": installations.as_array().map_or(0, Vec::len),
                "installations": installations
            })))
            .mount(mock)
    }

    async fn insert_user(
        state: &AppState,
        access: &str,
        refresh: &str,
        expires_at: DateTime<Utc>,
    ) -> Uuid {
        // user_id is generated app-side so the token ciphertexts can be
        // AAD-bound to it, same as the real callback path.
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email
            )
            VALUES ($1, 'coreyja', 12345, $2, $3, $4, 'corey@example.com')",
            user_id,
            state.crypto.encrypt(access, user_id.as_bytes()).unwrap(),
            state.crypto.encrypt(refresh, user_id.as_bytes()).unwrap(),
            expires_at
        )
        .execute(&state.db)
        .await
        .unwrap();
        user_id
    }

    #[tokio::test]
    async fn login_sets_state_cookie_and_redirects_to_github() {
        let state = lazy_test_state();
        let app = test_app(&state);

        let response = app
            .oneshot(Request::get("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let authorize_url = url::Url::parse(location(&response)).unwrap();
        assert!(
            authorize_url
                .as_str()
                .starts_with("https://github.invalid/login/oauth/authorize")
        );
        let pairs: std::collections::HashMap<_, _> = authorize_url.query_pairs().collect();
        assert_eq!(pairs["client_id"], "test-client-id");
        assert_eq!(pairs["redirect_uri"], "https://prn.test/callback");
        let state_param = &pairs["state"];
        assert_eq!(state_param.len(), 32);
        assert!(state_param.chars().all(|c| c.is_ascii_hexdigit()));

        let set_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|c| c.starts_with("oauth_state="))
            .expect("login must set the oauth_state cookie");
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Max-Age=600"));
        // The private jar encrypts the value; the raw state may not appear
        // in the wire cookie.
        assert!(!set_cookie.contains(state_param.as_ref()));
    }

    #[tokio::test]
    async fn callback_rejects_state_mismatch() {
        let state = lazy_test_state();
        let app = test_app(&state);

        let (real_state, cookies) = do_login(&app, "/login").await;
        let wrong_state = "0".repeat(32);
        assert_ne!(real_state, wrong_state);

        let response = do_callback(&app, &wrong_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The rejection must not leak the expected state, and the cookie is
        // single-use: it gets cleared even on mismatch.
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains(&real_state));
    }

    #[tokio::test]
    async fn callback_rejects_missing_state_cookie() {
        let state = lazy_test_state();
        let app = test_app(&state);

        let response = app
            .oneshot(
                Request::get(format!("/callback?code=test-code&state={}", "a".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn callback_clears_the_state_cookie_after_rejection() {
        let state = lazy_test_state();
        let app = test_app(&state);

        let (real_state, cookies) = do_login(&app, "/login").await;
        let rejection = do_callback(&app, &"0".repeat(32), &cookies).await;
        assert_eq!(rejection.status(), StatusCode::FORBIDDEN);

        // Honour the removal cookie the way a browser would: drop it.
        let removal = rejection
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with("oauth_state="))
            .expect("rejection must clear the state cookie");
        assert!(removal.contains("Max-Age=0") || removal.contains("Expires="));

        // Replaying the (now-cleared) state without the cookie is refused.
        let response = do_callback(&app, &real_state, "").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test]
    async fn callback_state_cannot_be_replayed_after_success(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let success = do_callback(&app, &oauth_state, &cookies).await;
        assert_eq!(success.status(), StatusCode::SEE_OTHER);

        // A browser now holds the session cookie and honoured the state
        // cookie's removal; replaying the same callback URL is refused.
        let post_success_cookies = cookie_header(&success);
        assert!(!post_success_cookies.contains("oauth_state"));
        let replay = do_callback(&app, &oauth_state, &post_success_cookies).await;
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test]
    async fn callback_signs_up_user_and_reaches_dashboard(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(
            &mock,
            serde_json::json!([{
                "id": 987,
                "account": { "login": "coreyja-studio" },
                "repository_selection": "selected"
            }]),
        )
        .await;
        let app = test_app(&state);

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let response = do_callback(&app, &oauth_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/dashboard");

        // The user row: tokens stored encrypted (and decryptable).
        let user = sqlx::query!("SELECT * FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.github_login, "coreyja");
        assert_eq!(user.github_user_id, 12345);
        assert_eq!(user.email, "corey@example.com");
        assert_eq!(user.status, "active");
        let aad = user.user_id.as_bytes();
        assert_eq!(
            state.crypto.decrypt(&user.access_token_enc, aad).unwrap(),
            "gho_test_access"
        );
        assert_eq!(
            state.crypto.decrypt(&user.refresh_token_enc, aad).unwrap(),
            "ghr_test_refresh"
        );
        assert!(user.token_expires_at > Utc::now() + chrono::Duration::hours(7));
        // Nothing token-shaped may be stored in the clear.
        assert_ne!(user.access_token_enc, b"gho_test_access");

        // The installation row and this user's link to it got upserted.
        let installation = sqlx::query!("SELECT * FROM installations")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(installation.installation_id, 987);
        assert_eq!(installation.account_login, "coreyja-studio");
        assert_eq!(installation.repository_selection, "selected");
        assert!(installation.last_seen_at.is_some());
        let link = sqlx::query!("SELECT * FROM user_installations")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(link.user_id, user.user_id);
        assert_eq!(link.installation_id, 987);

        // The session cookie carries SameSite=Lax and signs us into the
        // dashboard.
        let session_set_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with("session_id="))
            .expect("callback must set the session cookie");
        assert!(session_set_cookie.contains("SameSite=Lax"));
        assert!(session_set_cookie.contains("HttpOnly"));
        assert!(session_set_cookie.contains("Secure"));

        let session_cookies = cookie_header(&response);
        let dashboard = app
            .clone()
            .oneshot(
                Request::get("/dashboard")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dashboard.status(), StatusCode::OK);
        let body = axum::body::to_bytes(dashboard.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("coreyja"));
        assert!(body.contains("coreyja-studio"));

        // Logout (with the CSRF token rendered into the form) detaches the
        // user; the dashboard bounces to /login again.
        let csrf = extract_csrf(&body);
        assert_eq!(csrf, csrf_hex(&db).await);
        let logout = app
            .clone()
            .oneshot(post_form(
                "/logout",
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&logout), "/");

        let dashboard_after = app
            .clone()
            .oneshot(
                Request::get("/dashboard")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dashboard_after.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&dashboard_after), "/login");
    }

    #[sqlx::test]
    async fn callback_redirects_to_install_page_when_no_installations(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let response = do_callback(&app, &oauth_state, &cookies).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), github::INSTALL_URL);
    }

    #[sqlx::test]
    async fn relogin_rotates_tokens_and_clears_needs_reauth(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let user_id = insert_user(&state, "old_access", "old_refresh", Utc::now()).await;
        sqlx::query!(
            "UPDATE users SET status = 'needs_reauth' WHERE user_id = $1",
            user_id
        )
        .execute(&db)
        .await
        .unwrap();

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let response = do_callback(&app, &oauth_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let user = sqlx::query!("SELECT * FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        // Same user (upsert by github_user_id), fresh tokens, needs_reauth
        // cleared by the successful re-auth.
        assert_eq!(user.user_id, user_id);
        assert_eq!(user.status, "active");
        assert_eq!(
            state
                .crypto
                .decrypt(&user.access_token_enc, user_id.as_bytes())
                .unwrap(),
            "gho_test_access"
        );
    }

    #[sqlx::test]
    async fn fresh_token_is_returned_without_a_refresh(db: PgPool) {
        // No mock server at all: the .invalid base URLs in test_config make
        // any accidental HTTP call fail the test.
        let state = test_state(db, test_config());
        let user_id = insert_user(
            &state,
            "gho_still_fresh",
            "ghr_unused",
            Utc::now() + chrono::Duration::hours(2),
        )
        .await;

        let token = ensure_fresh_token(&state, user_id).await.unwrap();
        assert_eq!(token, "gho_still_fresh");
    }

    #[sqlx::test]
    async fn refresh_rotates_and_persists_both_tokens(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=ghr_old"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_new",
                "refresh_token": "ghr_new",
                "expires_in": 28800,
                "refresh_token_expires_in": 15_897_600,
                "token_type": "bearer",
                "scope": ""
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let user_id = insert_user(
            &state,
            "gho_old",
            "ghr_old",
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let token = ensure_fresh_token(&state, user_id).await.unwrap();
        assert_eq!(token, "gho_new");

        // Rotation: BOTH tokens and the expiry were persisted in one UPDATE.
        let user = sqlx::query!("SELECT * FROM users WHERE user_id = $1", user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            state
                .crypto
                .decrypt(&user.access_token_enc, user_id.as_bytes())
                .unwrap(),
            "gho_new"
        );
        assert_eq!(
            state
                .crypto
                .decrypt(&user.refresh_token_enc, user_id.as_bytes())
                .unwrap(),
            "ghr_new"
        );
        assert!(user.token_expires_at > Utc::now() + chrono::Duration::hours(7));
        assert_eq!(user.status, "active");
    }

    #[sqlx::test]
    async fn concurrent_refreshes_hit_github_once(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        // expect(1): the refresh token is single-use at GitHub, so a second
        // POST here would be the concurrency bug this test guards against.
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_new",
                "refresh_token": "ghr_new",
                "expires_in": 28800,
                "refresh_token_expires_in": 15_897_600,
                "token_type": "bearer",
                "scope": ""
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let user_id = insert_user(
            &state,
            "gho_old",
            "ghr_old",
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let (a, b) = tokio::join!(
            ensure_fresh_token(&state, user_id),
            ensure_fresh_token(&state, user_id)
        );
        // Both callers succeed: one refreshed, the other waited on the row
        // lock and returned the freshly-stored token.
        assert_eq!(a.unwrap(), "gho_new");
        assert_eq!(b.unwrap(), "gho_new");

        let user = sqlx::query!("SELECT status FROM users WHERE user_id = $1", user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.status, "active");
    }

    #[sqlx::test]
    async fn refresh_rejection_marks_user_needs_reauth(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        // GitHub reports OAuth failures as HTTP 200 + an error payload.
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "bad_refresh_token",
                "error_description": "The refresh token passed is incorrect or expired."
            })))
            .mount(&mock)
            .await;

        let user_id = insert_user(
            &state,
            "gho_old",
            "ghr_old",
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let result = ensure_fresh_token(&state, user_id).await;
        assert!(result.is_err());

        let user = sqlx::query!("SELECT * FROM users WHERE user_id = $1", user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.status, "needs_reauth");
        // The old pair is left in place (not clobbered with garbage).
        assert_eq!(
            state
                .crypto
                .decrypt(&user.access_token_enc, user_id.as_bytes())
                .unwrap(),
            "gho_old"
        );
        assert_eq!(
            state
                .crypto
                .decrypt(&user.refresh_token_enc, user_id.as_bytes())
                .unwrap(),
            "ghr_old"
        );
    }

    #[sqlx::test]
    async fn refresh_5xx_is_transient_and_does_not_mark_needs_reauth(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        // GitHub being down is not the user's fault: no needs_reauth.
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let user_id = insert_user(
            &state,
            "gho_old",
            "ghr_old",
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let result = ensure_fresh_token(&state, user_id).await;
        assert!(result.is_err());

        let user = sqlx::query!("SELECT * FROM users WHERE user_id = $1", user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.status, "active");
        assert_eq!(
            state
                .crypto
                .decrypt(&user.refresh_token_enc, user_id.as_bytes())
                .unwrap(),
            "ghr_old"
        );
    }

    #[sqlx::test]
    async fn expired_session_redirects_to_login_and_is_reaped(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = sign_in(&app).await;

        sqlx::query!("UPDATE user_sessions SET created_at = now() - interval '31 days'")
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
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/login");

        // The expired mapping was reaped, not left to linger.
        let mappings = sqlx::query_scalar!("SELECT count(*) FROM user_sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(mappings, Some(0));
    }

    #[sqlx::test]
    async fn disconnect_and_logout_require_a_valid_csrf_token(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let session_cookies = sign_in(&app).await;
        let good_csrf = csrf_hex(&db).await;

        // A cross-site form post rides the session cookie but cannot know
        // the per-session CSRF token.
        for body in [
            String::new(),
            format!("csrf={}", "0".repeat(64)),
            "csrf=".to_string(),
        ] {
            let response = app
                .clone()
                .oneshot(post_form("/disconnect", &session_cookies, body.clone()))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "body: {body:?}");

            let response = app
                .clone()
                .oneshot(post_form("/logout", &session_cookies, body.clone()))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "body: {body:?}");
        }

        // The account survived all of it, still signed in.
        let users = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, Some(1));
        let mappings = sqlx::query_scalar!("SELECT count(*) FROM user_sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(mappings, Some(1));

        // With the real token, logout works.
        let response = app
            .clone()
            .oneshot(post_form(
                "/logout",
                &session_cookies,
                format!("csrf={good_csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[sqlx::test]
    async fn disconnect_revokes_and_deletes_everything(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(
            &mock,
            serde_json::json!([{
                "id": 987,
                "account": { "login": "coreyja-studio" },
                "repository_selection": "all"
            }]),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path("/applications/test-client-id/grant"))
            .and(body_string_contains("gho_test_access"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock)
            .await;
        let app = test_app(&state);

        let session_cookies = sign_in(&app).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/disconnect",
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/");

        // The user and everything hanging off them is gone. The shared
        // installation row survives (it isn't this user's property), but the
        // link to it is gone.
        let users = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, Some(0));
        let links = sqlx::query_scalar!("SELECT count(*) FROM user_installations")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(links, Some(0));
        let mappings = sqlx::query_scalar!("SELECT count(*) FROM user_sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(mappings, Some(0));
        let sessions = sqlx::query_scalar!("SELECT count(*) FROM sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sessions, Some(0));
    }

    #[sqlx::test]
    async fn disconnect_refreshes_an_expired_token_before_revoking(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gho_refreshed",
                "refresh_token": "ghr_refreshed",
                "expires_in": 28800,
                "refresh_token_expires_in": 15_897_600,
                "token_type": "bearer",
                "scope": ""
            })))
            .expect(1)
            .mount(&mock)
            .await;
        // Revocation must use the *fresh* token, not the expired one.
        Mock::given(method("DELETE"))
            .and(path("/applications/test-client-id/grant"))
            .and(body_string_contains("gho_refreshed"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock)
            .await;
        let app = test_app(&state);

        let session_cookies = sign_in(&app).await;
        let csrf = csrf_hex(&db).await;
        sqlx::query!("UPDATE users SET token_expires_at = now() - interval '1 hour'")
            .execute(&db)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(post_form(
                "/disconnect",
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let users = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, Some(0));
    }

    #[sqlx::test]
    async fn disconnect_deletes_locally_even_when_revocation_fails(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        Mock::given(method("DELETE"))
            .and(path("/applications/test-client-id/grant"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let app = test_app(&state);

        let session_cookies = sign_in(&app).await;
        let csrf = csrf_hex(&db).await;

        let response = app
            .clone()
            .oneshot(post_form(
                "/disconnect",
                &session_cookies,
                format!("csrf={csrf}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let users = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, Some(0));
    }

    #[sqlx::test]
    async fn dashboard_requires_login(db: PgPool) {
        let state = test_state(db, test_config());
        let app = test_app(&state);

        let response = app
            .oneshot(Request::get("/dashboard").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/login");
    }
}
