use std::{convert::Infallible, time::Duration};

use cja::{
    cron::{CronRegistry, Worker},
    jobs::{CancellationToken, Job as _},
};

use crate::{jobs::SyncUser, state::AppState};

/// How often to fan out a sync across all active users.
const SYNC_SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How often to check every user for reviews that newly crossed their
/// staleness threshold. This is the reminder granularity: a review that
/// crosses at 4:31pm is emailed by the ~4:45pm sweep.
const REMINDER_SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Build the cron registry.
///
/// The closures are deliberately infallible (`Result<(), Infallible>`): a cron
/// closure that returns `Err` propagates up and crashes the whole app, so
/// [`sync_sweep`] and [`reminder_sweep`] handle every error internally
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
        "ReminderSweep",
        Some("Enqueue SendReminder for every active user"),
        REMINDER_SWEEP_INTERVAL,
        |state, _ctx| {
            Box::pin(async move {
                reminder_sweep(state).await;
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

/// Enqueue a [`SendReminder`](crate::jobs::SendReminder) job for every active
/// user. The job itself decides whether anything newly crossed the threshold
/// (and sends nothing otherwise), so the eligibility SQL lives in exactly one
/// place; most ticks are quiet no-ops. Never returns an error: all failures
/// are logged and the sweep continues.
async fn reminder_sweep(state: AppState) {
    let user_ids = match sqlx::query_scalar!("SELECT user_id FROM users WHERE status = 'active'")
        .fetch_all(&state.db)
        .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(?error, "ReminderSweep: failed to list active users");
            return;
        }
    };

    let total = user_ids.len();
    for user_id in user_ids {
        if let Err(error) = (crate::jobs::SendReminder { user_id })
            .enqueue(state.clone(), "reminder_sweep".to_string(), None)
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                "ReminderSweep: failed to enqueue SendReminder"
            );
        }
    }

    tracing::info!(active_users = total, "ReminderSweep enqueued");
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

    async fn insert_active_user(db: &PgPool, github_user_id: i64) -> Uuid {
        let state = test_state(db.clone(), test_config());
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email
            )
            VALUES ($1, 'test', $2, $3, $4, $5, 'test@example.com')",
            user_id,
            github_user_id,
            state.crypto.encrypt("tok", user_id.as_bytes()).unwrap(),
            state.crypto.encrypt("ref", user_id.as_bytes()).unwrap(),
            Utc::now() + Duration::days(30),
        )
        .execute(db)
        .await
        .unwrap();
        user_id
    }

    #[sqlx::test]
    async fn reminder_sweep_enqueues_for_every_active_user(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        insert_active_user(&db, 1).await;
        insert_active_user(&db, 2).await;

        reminder_sweep(state).await;

        let job_count =
            sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendReminder'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(job_count, Some(2));
    }

    #[sqlx::test]
    async fn reminder_sweep_skips_inactive_users(db: PgPool) {
        let state = test_state(db.clone(), test_config());
        let paused = insert_active_user(&db, 1).await;
        sqlx::query!(
            "UPDATE users SET status = 'paused' WHERE user_id = $1",
            paused
        )
        .execute(&db)
        .await
        .unwrap();
        let needs_reauth = insert_active_user(&db, 2).await;
        sqlx::query!(
            "UPDATE users SET status = 'needs_reauth' WHERE user_id = $1",
            needs_reauth
        )
        .execute(&db)
        .await
        .unwrap();

        reminder_sweep(state).await;

        let job_count =
            sqlx::query_scalar!("SELECT COUNT(*) FROM jobs WHERE name = 'SendReminder'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(job_count, Some(0));
    }
}
