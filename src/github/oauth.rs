//! GitHub OAuth web flow (user-to-server): /login, /callback, and the
//! token refresh helper used by sync jobs.
//!
//! Security invariants (see the PR checklist):
//! - The state cookie is HttpOnly + Secure + SameSite=Lax, Max-Age 600,
//!   stored in cja's *private* (encrypted) cookie jar, and cleared on use.
//! - Tokens are never logged and only ever stored encrypted.
//! - Refresh tokens rotate: the new pair is persisted in a single UPDATE
//!   *before* the new access token is returned to the caller.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Redirect, Response},
};
use chrono::Utc;
use cja::server::{
    cookies::{Cookie, CookieJar, SameSite},
    session::AppSession as _,
};
use color_eyre::eyre::eyre;
use rand::RngCore as _;
use serde::Deserialize;
use uuid::Uuid;

use crate::{github, session::PrnSession, state::AppState};

/// Name of the (encrypted) cookie carrying the OAuth state and optional
/// signup timezone, as `"{state}"` or `"{state}|{iana_tz}"`.
const STATE_COOKIE: &str = "oauth_state";

#[derive(Deserialize)]
pub struct LoginParams {
    /// IANA timezone captured client-side; validated before use.
    tz: Option<String>,
}

/// `GET /login` — set the state cookie and bounce to GitHub's authorize URL.
pub async fn login(
    State(state): State<AppState>,
    Query(params): Query<LoginParams>,
    jar: CookieJar<AppState>,
) -> Response {
    // 32 hex chars = 128 bits of CSRF entropy.
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let oauth_state = bytes.map(|b| format!("{b:02x}")).concat();

    // Only carry a tz we can actually parse; anything else is dropped.
    let tz = params
        .tz
        .as_deref()
        .filter(|tz| tz.parse::<chrono_tz::Tz>().is_ok());
    let cookie_value = match tz {
        Some(tz) => format!("{oauth_state}|{tz}"),
        None => oauth_state.clone(),
    };

    let cookie = Cookie::build((STATE_COOKIE, cookie_value))
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
    let stored_value = stored.value();
    let (expected_state, tz) = match stored_value.split_once('|') {
        Some((state, tz)) => (state, Some(tz.to_string())),
        None => (stored_value, None),
    };

    if params.state.as_deref() != Some(expected_state) {
        return (StatusCode::FORBIDDEN, "OAuth state mismatch").into_response();
    }

    let Some(code) = params.code.as_deref() else {
        // e.g. the user cancelled the authorization prompt.
        return (StatusCode::BAD_REQUEST, "Missing authorization code").into_response();
    };

    match signed_in_response(&app_state, code, tz, &jar).await {
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
    tz: Option<String>,
    jar: &CookieJar<AppState>,
) -> cja::Result<Response> {
    let tokens = exchange_code(state, code).await?;

    let viewer = github::fetch_viewer(state, &tokens.access_token).await?;
    let email = github::fetch_primary_email(state, &tokens.access_token).await?;

    let access_token_enc = state.crypto.encrypt(&tokens.access_token)?;
    let refresh_token_enc = state.crypto.encrypt(&tokens.refresh_token)?;
    let token_expires_at = Utc::now() + chrono::Duration::seconds(tokens.expires_in);

    // Upsert by the rename-stable github_user_id. The timezone is only taken
    // from the login flow while the column still holds the default 'UTC' — a
    // user-chosen timezone is never clobbered by a re-login. A re-login also
    // clears needs_reauth (the user just proved they can auth), but leaves a
    // deliberate 'paused' alone.
    let user_id = sqlx::query_scalar!(
        r#"
        INSERT INTO users (
            github_login, github_user_id, access_token_enc, refresh_token_enc,
            token_expires_at, email, timezone
        )
        VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::text, 'UTC'))
        ON CONFLICT (github_user_id) DO UPDATE SET
            github_login = EXCLUDED.github_login,
            email = EXCLUDED.email,
            access_token_enc = EXCLUDED.access_token_enc,
            refresh_token_enc = EXCLUDED.refresh_token_enc,
            token_expires_at = EXCLUDED.token_expires_at,
            timezone = CASE
                WHEN users.timezone = 'UTC' THEN COALESCE($7::text, users.timezone)
                ELSE users.timezone
            END,
            status = CASE
                WHEN users.status = 'needs_reauth' THEN 'active'
                ELSE users.status
            END
        RETURNING user_id
        "#,
        viewer.login,
        viewer.database_id,
        access_token_enc,
        refresh_token_enc,
        token_expires_at,
        email,
        tz.as_deref(),
    )
    .fetch_one(&state.db)
    .await?;

    let installations = github::fetch_user_installations(state, &tokens.access_token).await?;
    for installation in &installations {
        sqlx::query!(
            r#"
            INSERT INTO installations (
                installation_id, account_login, user_id, repository_selection, last_seen_at
            )
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (installation_id) DO UPDATE SET
                account_login = EXCLUDED.account_login,
                user_id = EXCLUDED.user_id,
                repository_selection = EXCLUDED.repository_selection,
                last_seen_at = now()
            "#,
            installation.id,
            installation.account_login,
            user_id,
            installation.repository_selection,
        )
        .execute(&state.db)
        .await?;
    }

    // Fresh session per sign-in; save the cookie the same way cja does.
    let session = PrnSession::create(&state.db).await?;
    session.set_user(&state.db, user_id).await?;
    let session_cookie = Cookie::build(("session_id", session.session_id().to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .build();
    jar.add(session_cookie);

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
    /// GitHub answered and said no (OAuth error payload or non-2xx status).
    Rejected(color_eyre::Report),
    /// We never got a usable answer (network, deserialization, ...).
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
/// On a definitive refresh rejection (e.g. `bad_refresh_token`) the user is
/// marked `needs_reauth` and an error is returned. Transient transport
/// failures return an error without changing the user's status, so a GitHub
/// blip doesn't force everyone back through OAuth.
///
/// Public API for the sync jobs landing in the next PR.
#[allow(dead_code)] // Exercised by tests today; sync jobs are the real caller.
pub async fn ensure_fresh_token(state: &AppState, user_id: Uuid) -> cja::Result<String> {
    let row = sqlx::query!(
        "SELECT access_token_enc, refresh_token_enc, token_expires_at
         FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    if row.token_expires_at > Utc::now() + chrono::Duration::minutes(5) {
        return state.crypto.decrypt(&row.access_token_enc);
    }

    let refresh_token = state.crypto.decrypt(&row.refresh_token_enc)?;
    let form = [
        ("client_id", state.config.github_client_id.as_str()),
        ("client_secret", state.config.github_client_secret.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
    ];

    match token_request(state, &form).await {
        Ok(pair) => {
            let access_token_enc = state.crypto.encrypt(&pair.access_token)?;
            let refresh_token_enc = state.crypto.encrypt(&pair.refresh_token)?;
            let token_expires_at = Utc::now() + chrono::Duration::seconds(pair.expires_in);

            // Refresh tokens rotate: persist BOTH new tokens atomically, and
            // do it before handing the new access token to the caller — if we
            // die after this statement nothing is lost, whereas using the
            // token first and persisting later could strand the new refresh
            // token and lock the user out.
            sqlx::query!(
                "UPDATE users
                 SET access_token_enc = $1, refresh_token_enc = $2, token_expires_at = $3
                 WHERE user_id = $4",
                access_token_enc,
                refresh_token_enc,
                token_expires_at,
                user_id
            )
            .execute(&state.db)
            .await?;

            Ok(pair.access_token)
        }
        Err(TokenRequestError::Rejected(report)) => {
            sqlx::query!(
                "UPDATE users SET status = 'needs_reauth' WHERE user_id = $1",
                user_id
            )
            .execute(&state.db)
            .await?;
            Err(report.wrap_err("GitHub rejected the refresh token; user marked needs_reauth"))
        }
        Err(TokenRequestError::Transport(report)) => {
            Err(report.wrap_err("token refresh request failed"))
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

    /// Collapse a response's Set-Cookie headers into a Cookie request header.
    fn cookie_header(response: &axum::response::Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
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
        sqlx::query_scalar!(
            "INSERT INTO users (
                github_login, github_user_id, access_token_enc, refresh_token_enc,
                token_expires_at, email
            )
            VALUES ('coreyja', 12345, $1, $2, $3, 'corey@example.com')
            RETURNING user_id",
            state.crypto.encrypt(access).unwrap(),
            state.crypto.encrypt(refresh).unwrap(),
            expires_at
        )
        .fetch_one(&state.db)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn login_sets_state_cookie_and_redirects_to_github() {
        let state = lazy_test_state();
        let app = test_app(&state);

        let response = app
            .oneshot(
                Request::get("/login?tz=America/New_York")
                    .body(Body::empty())
                    .unwrap(),
            )
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
        // The private jar encrypts the value; neither the raw state nor the
        // tz may appear in the wire cookie.
        assert!(!set_cookie.contains(state_param.as_ref()));
        assert!(!set_cookie.contains("America/New_York"));
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

        let (oauth_state, cookies) = do_login(&app, "/login?tz=America/New_York").await;
        let response = do_callback(&app, &oauth_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/dashboard");

        // The user row: tokens stored encrypted (and decryptable), tz captured.
        let user = sqlx::query!("SELECT * FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.github_login, "coreyja");
        assert_eq!(user.github_user_id, 12345);
        assert_eq!(user.email, "corey@example.com");
        assert_eq!(user.timezone, "America/New_York");
        assert_eq!(user.status, "active");
        assert_eq!(
            state.crypto.decrypt(&user.access_token_enc).unwrap(),
            "gho_test_access"
        );
        assert_eq!(
            state.crypto.decrypt(&user.refresh_token_enc).unwrap(),
            "ghr_test_refresh"
        );
        assert!(user.token_expires_at > Utc::now() + chrono::Duration::hours(7));
        // Nothing token-shaped may be stored in the clear.
        assert_ne!(user.access_token_enc, b"gho_test_access");

        // The installation got upserted.
        let installation = sqlx::query!("SELECT * FROM installations")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(installation.installation_id, 987);
        assert_eq!(installation.account_login, "coreyja-studio");
        assert_eq!(installation.repository_selection, "selected");
        assert_eq!(installation.user_id, Some(user.user_id));
        assert!(installation.last_seen_at.is_some());

        // The session cookie signs us into the dashboard.
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

        // Logout detaches the user; the dashboard bounces to /login again.
        let logout = app
            .clone()
            .oneshot(
                Request::post("/logout")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
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

        // Timezone defaults to UTC when the login link carried no tz.
        let user = sqlx::query!("SELECT timezone FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(user.timezone, "UTC");
    }

    #[sqlx::test]
    async fn relogin_does_not_clobber_user_chosen_timezone(db: PgPool) {
        let (state, mock) = mock_backed_state(db.clone()).await;
        mount_token_exchange(&mock).await;
        mount_user_endpoints(&mock).await;
        mount_installations(&mock, serde_json::json!([])).await;
        let app = test_app(&state);

        let user_id = insert_user(&state, "old_access", "old_refresh", Utc::now()).await;
        sqlx::query!(
            "UPDATE users SET timezone = 'Europe/Berlin', status = 'needs_reauth' WHERE user_id = $1",
            user_id
        )
        .execute(&db)
        .await
        .unwrap();

        let (oauth_state, cookies) = do_login(&app, "/login?tz=America/New_York").await;
        let response = do_callback(&app, &oauth_state, &cookies).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let user = sqlx::query!("SELECT * FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        // Same user (upsert by github_user_id), fresh tokens, tz preserved,
        // needs_reauth cleared by the successful re-auth.
        assert_eq!(user.user_id, user_id);
        assert_eq!(user.timezone, "Europe/Berlin");
        assert_eq!(user.status, "active");
        assert_eq!(
            state.crypto.decrypt(&user.access_token_enc).unwrap(),
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
            state.crypto.decrypt(&user.access_token_enc).unwrap(),
            "gho_new"
        );
        assert_eq!(
            state.crypto.decrypt(&user.refresh_token_enc).unwrap(),
            "ghr_new"
        );
        assert!(user.token_expires_at > Utc::now() + chrono::Duration::hours(7));
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
            state.crypto.decrypt(&user.access_token_enc).unwrap(),
            "gho_old"
        );
        assert_eq!(
            state.crypto.decrypt(&user.refresh_token_enc).unwrap(),
            "ghr_old"
        );
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

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let signed_in = do_callback(&app, &oauth_state, &cookies).await;
        let session_cookies = cookie_header(&signed_in);

        let response = app
            .clone()
            .oneshot(
                Request::post("/disconnect")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/");

        // Everything is gone: user, installations (CASCADE), session mapping,
        // and the session row itself.
        let users = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, Some(0));
        let installations = sqlx::query_scalar!("SELECT count(*) FROM installations")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(installations, Some(0));
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

        let (oauth_state, cookies) = do_login(&app, "/login").await;
        let signed_in = do_callback(&app, &oauth_state, &cookies).await;
        let session_cookies = cookie_header(&signed_in);

        let response = app
            .clone()
            .oneshot(
                Request::post("/disconnect")
                    .header(header::COOKIE, &session_cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
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
