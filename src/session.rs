//! App sessions on top of cja's session machinery.
//!
//! cja owns the `sessions` table and the `session_id` cookie; we attach the
//! signed-in user via the `user_sessions` mapping table (one row per
//! signed-in session; no row means anonymous).

use axum::{
    extract::FromRequestParts,
    http::StatusCode,
    response::{IntoResponse as _, Redirect, Response},
};
use cja::server::session::{AppSession, CJASession, Session};
use sqlx::PgPool;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct PrnSession {
    inner: CJASession,
    pub user_id: Option<Uuid>,
}

#[async_trait::async_trait]
impl AppSession for PrnSession {
    async fn from_db(pool: &PgPool, session_id: Uuid) -> cja::Result<Self> {
        let row = sqlx::query!(
            r#"
            SELECT s.session_id, s.created_at, s.updated_at, us.user_id AS "user_id?"
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
        })
    }

    async fn create(pool: &PgPool) -> cja::Result<Self> {
        let inner = sqlx::query_as!(
            CJASession,
            "INSERT INTO sessions DEFAULT VALUES RETURNING session_id, updated_at, created_at"
        )
        .fetch_one(pool)
        .await?;

        Ok(Self {
            inner,
            user_id: None,
        })
    }

    fn from_inner(inner: CJASession) -> Self {
        Self {
            inner,
            user_id: None,
        }
    }

    fn inner(&self) -> &CJASession {
        &self.inner
    }
}

impl PrnSession {
    /// Attach a user to this session (sign in).
    pub async fn set_user(&self, pool: &PgPool, user_id: Uuid) -> cja::Result<()> {
        sqlx::query!(
            "INSERT INTO user_sessions (session_id, user_id) VALUES ($1, $2)
             ON CONFLICT (session_id) DO UPDATE SET user_id = EXCLUDED.user_id",
            *self.session_id(),
            user_id
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

/// Extractor for routes that require a signed-in user.
///
/// Rejects with a redirect to `/login` when the session has no user (or the
/// user row has since been deleted).
pub struct CurrentUser {
    pub session: PrnSession,
    pub user_id: Uuid,
    pub github_login: String,
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

        let Some(user_id) = session.user_id else {
            return Err(Redirect::to("/login").into_response());
        };

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
        })
    }
}
