use std::{convert::Infallible, time::Duration};

use cja::{
    cron::{CronRegistry, Worker},
    jobs::{CancellationToken, Job as _},
};

use crate::{jobs::SyncUser, state::AppState};

/// How often to fan out a sync across all active users.
const SYNC_SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Build the cron registry.
///
/// The closure is deliberately infallible (`Result<(), Infallible>`): a cron
/// closure that returns `Err` propagates up and crashes the whole app, so
/// [`sync_sweep`] handles every error internally (log-and-continue) and this
/// wrapper can only ever return `Ok`.
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
