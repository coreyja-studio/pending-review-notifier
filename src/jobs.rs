use cja::jobs::Job;

use crate::state::AppState;

/// Placeholder job so the job registry has at least one entry.
///
/// Note on error handling: errors returned from `Job::run` are caught by
/// cja's job worker — the job is retried with exponential backoff and
/// dead-lettered after max retries; they do NOT crash the app. The gotcha
/// to watch is cron *closures* (see src/cron.rs), whose errors do propagate
/// and crash the whole app.
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
