//! App sessions on top of cja's session machinery.
//!
//! cja owns the `sessions` table and the `session_id` cookie; we attach the
//! signed-in user via the `user_sessions` mapping table (one row per
//! signed-in session; no row means anonymous). The mapping row also carries
//! the per-session CSRF token and the sign-in timestamp used for expiry.

use axum::{
    extract::FromRequestParts,
    http::StatusCode,
    response::{IntoResponse as _, Redirect, Response},
};
use cja::server::session::{AppSession, CJASession, Session};
use rand::RngCore as _;
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::state::AppState;

/// Signed-in sessions older than this are rejected and reaped on next use.
pub const SESSION_MAX_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct PrnSession {
    inner: CJASession,
    pub user_id: Option<Uuid>,
    /// Per-session CSRF token; present iff `user_id` is.
    pub csrf_token: Option<Vec<u8>>,
    /// When the user signed in (user_sessions.created_at); present iff
    /// `user_id` is.
    pub signed_in_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[async_trait::async_trait]
impl AppSession for PrnSession {
    async fn from_db(pool: &PgPool, session_id: Uuid) -> cja::Result<Self> {
        let row = sqlx::query!(
            r#"
            SELECT s.session_id, s.created_at, s.updated_at,
                   us.user_id AS "user_id?",
                   us.csrf_token AS "csrf_token?",
                   us.created_at AS "signed_in_at?"
            FROM sessions s
            LEFT JOIN user_sessions us ON us.session_id = s.session_id
            WHERE s.session_id = $1
            "#,
            session_id
        )
        .fetch_one(pool)
        .await?;

        Ok(Self {
            inner: CJASession {
                session_id: row.session_id,
                updated_at: row.updated_at,
                created_at: row.created_at,
            },
            user_id: row.user_id,
            csrf_token: row.csrf_token,
            signed_in_at: row.signed_in_at,
        })
    }

    async fn create(pool: &PgPool) -> cja::Result<Self> {
        let inner = sqlx::query_as!(
            CJASession,
            "INSERT INTO sessions DEFAULT VALUES RETURNING session_id, updated_at, created_at"
        )
        .fetch_one(pool)
        .await?;

        Ok(Self::from_inner(inner))
    }

    fn from_inner(inner: CJASession) -> Self {
        Self {
            inner,
            user_id: None,
            csrf_token: None,
            signed_in_at: None,
        }
    }

    fn inner(&self) -> &CJASession {
        &self.inner
    }
}

impl PrnSession {
    /// Attach a user to this session (sign in), minting a fresh CSRF token.
    pub async fn set_user(&self, pool: &PgPool, user_id: Uuid) -> cja::Result<()> {
        let mut csrf_token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut csrf_token);

        sqlx::query!(
            "INSERT INTO user_sessions (session_id, user_id, csrf_token)
             VALUES ($1, $2, $3)
             ON CONFLICT (session_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                csrf_token = EXCLUDED.csrf_token,
                created_at = now()",
            *self.session_id(),
            user_id,
            &csrf_token
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Detach the user from this session (log out); the session itself lives on.
    pub async fn clear_user(&self, pool: &PgPool) -> cja::Result<()> {
        sqlx::query!(
            "DELETE FROM user_sessions WHERE session_id = $1",
            *self.session_id()
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Delete the session row entirely (cascades the user mapping).
    pub async fn destroy(&self, pool: &PgPool) -> cja::Result<()> {
        sqlx::query!(
            "DELETE FROM sessions WHERE session_id = $1",
            *self.session_id()
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}

/// Constant-time comparison of the stored CSRF token against the hex value
/// submitted in a form. Length differences short-circuit inside `ct_eq`,
/// which is fine — the length is not a secret.
pub fn csrf_matches(expected: &[u8], provided_hex: &str) -> bool {
    // An empty expected token must never match (defensive: it can't happen
    // with the NOT NULL column, but empty == empty would be a bypass).
    if expected.is_empty() {
        return false;
    }
    let expected_hex = hex::encode(expected);
    expected_hex
        .as_bytes()
        .ct_eq(provided_hex.as_bytes())
        .into()
}

/// Extractor for routes that require a signed-in user.
///
/// Rejects with a redirect to `/login` when the session has no user, the
/// user row has since been deleted, or the sign-in is older than
/// [`SESSION_MAX_AGE_DAYS`] (in which case the stale mapping is reaped).
pub struct CurrentUser {
    pub session: PrnSession,
    pub user_id: Uuid,
    pub github_login: String,
    /// Per-session CSRF token for state-changing forms.
    pub csrf_token: Vec<u8>,
}

impl CurrentUser {
    /// Hex form of the CSRF token, as rendered into hidden form inputs.
    pub fn csrf_hex(&self) -> String {
        hex::encode(&self.csrf_token)
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::<PrnSession>::from_request_parts(parts, state)
            .await
            .map_err(axum::response::IntoResponse::into_response)?;

        let (Some(user_id), Some(csrf_token), Some(signed_in_at)) = (
            session.user_id,
            session.csrf_token.clone(),
            session.signed_in_at,
        ) else {
            return Err(Redirect::to("/login").into_response());
        };

        // Expire (and reap) old sign-ins rather than letting them live forever.
        if signed_in_at < chrono::Utc::now() - chrono::Duration::days(SESSION_MAX_AGE_DAYS) {
            if let Err(err) = session.clear_user(&state.db).await {
                tracing::error!(?err, "Failed to reap an expired session mapping");
            }
            return Err(Redirect::to("/login").into_response());
        }

        let row = sqlx::query!("SELECT github_login FROM users WHERE user_id = $1", user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|err| {
                tracing::error!(?err, "Failed to load current user");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

        // A mapping pointing at a deleted user is stale; treat as signed out.
        let Some(row) = row else {
            return Err(Redirect::to("/login").into_response());
        };

        Ok(Self {
            session,
            user_id,
            github_login: row.github_login,
            csrf_token,
        })
    }
}
