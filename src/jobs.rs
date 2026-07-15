use cja::jobs::Job;

use crate::state::AppState;

/// Placeholder job so the job registry has at least one entry.
///
/// IMPORTANT cja gotcha for future jobs: errors returned from job/cron
/// closures propagate up and can crash the whole app. Real jobs (SyncUser,
/// SendDigest, ...) must wrap their bodies to log errors and return `Ok`
/// at the top level instead of bubbling failures with `?`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoopJob;

#[async_trait::async_trait]
impl Job<AppState> for NoopJob {
    const NAME: &'static str = "NoopJob";

    async fn run(&self, _app_state: AppState) -> cja::Result<()> {
        tracing::info!("NoopJob ran");
        Ok(())
    }
}

cja::impl_job_registry!(AppState, NoopJob);
