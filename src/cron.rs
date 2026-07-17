use std::{convert::Infallible, time::Duration};

use chrono::Timelike;
use cja::{
    cron::{CronRegistry, Worker},
    jobs::{CancellationToken, Job as _},
};

use crate::{jobs::SyncUser, state::AppState};

/// How often to fan out a sync across all active users.
const SYNC_SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How often to check if any user's local hour matches their digest hour.
const DIGEST_SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Build the cron registry.
///
/// The closures are deliberately infallible (`Result<(), Infallible>`): a cron
/// closure that returns `Err` propagates up and crashes the whole app, so
/// [`sync_sweep`] and [`digest_sweep`] handle every error internally
/// (log-and-continue) and the wrappers can only ever return `Ok`.
fn registry() -> CronRegistry<AppState> {
    let mut registry = CronRegistry::new();
    registry.register(
        "SyncSweep",
        Some("Enqueue a SyncUser job for every active user"),
        SYNC_SWEEP_INTERVAL,
        |state, _ctx| {
            Box::pin(async move {
                sync_sweep(state).await;
                Ok::<(), Infallible>(())
            })
        },
    );
    registry.register(
        "DigestSweep",
        Some("Enqueue SendDigest for each active user at their local digest hour"),
        DIGEST_SWEEP_INTERVAL,
        |state, _ctx| {
            Box::pin(async move {
                digest_sweep(state).await;
                Ok::<(), Infallible>(())
            })
        },
    );
    registry
}

/// Enqueue a [`SyncUser`] job for every `active` user. Never returns an error:
/// a failed user list or a failed enqueue is logged and the sweep continues, so
/// one bad row cannot crash the cron worker or block the rest of the fan-out.
async fn sync_sweep(state: AppState) {
    let user_ids = match sqlx::query_scalar!("SELECT user_id FROM users WHERE status = 'active'")
        .fetch_all(&state.db)
        .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(?error, "SyncSweep: failed to list active users");
            return;
        }
    };

    let total = user_ids.len();
    for user_id in user_ids {
        if let Err(error) = (SyncUser { user_id })
            .enqueue(state.clone(), "sync_sweep".to_string(), None)
            .await
        {
            tracing::error!(?error, %user_id, "SyncSweep: failed to enqueue SyncUser");
        }
    }

    tracing::info!(active_users = total, "SyncSweep enqueued");
}

/// For each active user, compute their local hour via their IANA timezone. If
/// it equals their `digest_hour` and no digest was sent in ~20h, enqueue a
/// [`SendDigest`](crate::jobs::SendDigest) job. Never returns an error: all
/// failures are logged and the sweep continues.
async fn digest_sweep(state: AppState) {
    let users = match sqlx::query!(
        "SELECT user_id, timezone, digest_hour, last_digest_at
         FROM users WHERE status = 'active'"
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(users) => users,
        Err(error) => {
            tracing::error!(?error, "DigestSweep: failed to list active users");
            return;
        }
    };

    let now = chrono::Utc::now();
    for user in users {
        let Ok(tz) = user.timezone.parse::<chrono_tz::Tz>() else {
            tracing::warn!(
                user_id = %user.user_id,
                timezone = %user.timezone,
                "DigestSweep: invalid timezone, skipping user"
            );
            continue;
        };

        let local_hour = now.with_timezone(&tz).hour();
        let hour_matches = u32::try_from(user.digest_hour)
            .map(|h| h == local_hour)
            .unwrap_or(false);
        if !hour_matches {
            continue;
        }

        let should_send = user
            .last_digest_at
            .is_none_or(|t| now - t > chrono::Duration::hours(20));
        if !should_send {
            continue;
        }

        if let Err(error) = (crate::jobs::SendDigest {
            user_id: user.user_id,
        })
        .enqueue(state.clone(), "digest_sweep".to_string(), None)
        .await
        {
            tracing::error!(
                ?error,
                user_id = %user.user_id,
                "DigestSweep: failed to enqueue SendDigest"
            );
        }
    }

    tracing::info!("DigestSweep completed");
}

pub async fn run_cron(app_state: AppState, shutdown_token: CancellationToken) -> cja::Result<()> {
    Worker::new_with_timezone(
        app_state,
        registry(),
        cja::chrono_tz::UTC,
        Duration::from_secs(60),
    )
    .run(shutdown_token)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::*;
    use crate::state::test_support::{test_config, test_state};

    async fn insert_active_user(
        db: &PgPool,
        timezone: &str,
        digest_hour: i32,
        last_digest_at: Option<chrono::DateTime<Utc>>,
    ) -> Uuid {
        let state = test_state(db.clone(), test_config());
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email, timezone, digest_hour, last_digest_at
            )
            VALUES ($1, 'test', 12345, $2, $3, $4, 'test@example.com', $5, $6, $7)",
            user_id,
            state.crypto.encrypt("tok", user_id.as_bytes()).unwrap(),
            state.crypto.encrypt("ref", user_id.as_bytes()).unwrap(),
            Utc::now() + Duration::days(30),
            timezone,
            digest_hour,
            last_digest_at,
        )
        .execute(db)
        .await
        .unwrap();
        user_id
    }

    #[sqlx::test]
    async fn digest_sweep_enqueues_for_matching_hour(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        insert_active_user(&db, "UTC", current_hour, None).await;

        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(1));
    }

    #[sqlx::test]
    async fn digest_sweep_skips_non_matching_hour(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        let non_matching_hour = if current_hour == 0 { 1 } else { 0 };
        insert_active_user(&db, "UTC", non_matching_hour, None).await;

        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(0));
    }

    #[sqlx::test]
    async fn digest_sweep_skips_recently_sent(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        // Just sent a digest 1 hour ago — within the 20h window
        insert_active_user(
            &db,
            "UTC",
            current_hour,
            Some(Utc::now() - Duration::hours(1)),
        )
        .await;

        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(0));
    }

    #[sqlx::test]
    async fn digest_sweep_sends_after_20h(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        // Last digest was 21 hours ago — past the 20h window
        insert_active_user(
            &db,
            "UTC",
            current_hour,
            Some(Utc::now() - Duration::hours(21)),
        )
        .await;

        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(1));
    }

    #[sqlx::test]
    async fn digest_sweep_skips_inactive_users(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        let user_id = insert_active_user(&db, "UTC", current_hour, None).await;
        sqlx::query!(
            "UPDATE users SET status = 'paused' WHERE user_id = $1",
            user_id
        )
        .execute(&db)
        .await
        .unwrap();

        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(0));
    }

    #[sqlx::test]
    async fn digest_sweep_skips_invalid_timezone(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let current_hour = Utc::now().hour() as i32;
        insert_active_user(&db, "Not/A/Zone", current_hour, None).await;

        // Should not panic
        digest_sweep(state).await;

        let job_count = sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendDigest'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(job_count, Some(0));
    }
}
