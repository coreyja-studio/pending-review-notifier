use std::time::Duration;

use cja::{
    cron::{CronRegistry, Worker},
    jobs::CancellationToken,
};

use crate::state::AppState;

/// Build the cron registry.
///
/// Empty for now — SyncSweep and DigestSweep land in a later PR. When they
/// do, remember the cja gotcha: a cron closure returning `Err` crashes the
/// whole app, so job bodies must log-and-continue instead of propagating.
fn registry() -> CronRegistry<AppState> {
    CronRegistry::new()
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
