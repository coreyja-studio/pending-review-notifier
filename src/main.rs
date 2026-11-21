use std::time::Duration;

use cja::{
    jobs::{DEFAULT_MAX_RETRIES, JobWorkerConfig, worker::job_worker},
    server::run_server_until,
    setup::TracingConfig,
    tasks::{ShutdownBudget, Supervisor},
};

mod cron;
mod crypto;
mod discovery;
mod email;
mod github;
mod jobs;
mod routes;
mod session;
mod state;

use state::AppState;

/// Shutdown budget, sized for fly.toml's `kill_signal = "SIGTERM"` +
/// `kill_timeout = "10s"`: 6s for tasks, leaving up to ~3s for telemetry.
///
/// An in-flight job gets 5s to finish. `SyncUser` and `SendReminder` are a
/// handful of GitHub/MailPace round trips, so that lets nearly all of them
/// complete instead of being re-run (a `SendReminder` dropped between the
/// send and the `notified_at` stamp re-sends the email on retry). Whatever is
/// still running after 5s is dropped with its lock released, so the next
/// boot claims it at once rather than waiting for lock reclamation. The
/// remaining 1s covers lock release, cron, and HTTP shutdown.
const SHUTDOWN_BUDGET: ShutdownBudget = ShutdownBudget {
    job_drain: Duration::from_secs(5),
    exit_grace: Duration::from_secs(1),
};

fn main() -> cja::Result<()> {
    color_eyre::install()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> cja::Result<()> {
    let telemetry_handle = TracingConfig::new("prn")
        .version(env!("CARGO_PKG_VERSION"))
        .init()?;

    let result = run_tasks().await;
    if let Err(error) = &result {
        tracing::error!(error = %format_args!("{error:#}"), "application tasks failed");
    }
    let flush = telemetry_handle.shutdown().await;
    if result.is_ok() {
        flush?;
    }
    result
}

async fn run_tasks() -> cja::Result<()> {
    let app_state = AppState::from_env().await?;

    // Build the cron registry once so it can seed the Eyes boot manifest
    // before being handed off to the cron worker.
    let cron_registry = cron::registry();

    // Eyes is optional. A local APP_BASE_URL cannot be used for an external
    // HTTP check, but the job and cron declarations are still useful.
    cja::eyes_manifest::send_manifest(eyes_boot_manifest(&app_state, &cron_registry));

    cja::posthog_manifest::emit_boot_manifest::<jobs::Jobs, AppState>(
        &app_state,
        &cja::posthog_manifest::BootManifest::new("prn", &cron_registry, &cron::TIMEZONE, &[], &[]),
    )?;

    // The supervisor registers SIGTERM + SIGINT, owns the shutdown token the
    // server, job worker and cron all watch, and runs the drain.
    let mut supervisor = Supervisor::new(SHUTDOWN_BUDGET)?;
    let shutdown = supervisor.shutdown_token();

    tracing::info!("Spawning tasks");
    supervisor.spawn(
        "server",
        run_server_until(
            routes::routes().with_state(app_state.clone()),
            shutdown.clone().cancelled_owned(),
        ),
    );
    supervisor.spawn(
        "job_worker",
        job_worker(
            app_state.clone(),
            jobs::Jobs,
            Duration::from_secs(5),
            DEFAULT_MAX_RETRIES,
            shutdown.clone(),
            JobWorkerConfig {
                shutdown_drain_timeout: supervisor.budget().job_drain,
                ..JobWorkerConfig::default()
            },
        ),
    );
    supervisor.spawn(
        "cron_worker",
        cron::run_cron(app_state, cron_registry, shutdown),
    );

    supervisor.run().await
}

fn eyes_boot_manifest(
    state: &AppState,
    cron_registry: &cja::cron::CronRegistry<AppState>,
) -> cja::eyes_manifest::AppManifest {
    match cja::eyes_manifest::build_boot_manifest_from_state::<jobs::Jobs, AppState>(
        state,
        Some(env!("CARGO_PKG_VERSION")),
        None,
        Some(cron_registry),
    ) {
        Ok(manifest) => manifest,
        Err(error) => {
            tracing::warn!(%error, "Eyes HTTP monitor declaration unavailable; sending jobs and crons");
            cja::eyes_manifest::build_boot_manifest::<jobs::Jobs, AppState>(
                Some(env!("CARGO_PKG_VERSION")),
                None,
                Some(cron_registry),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn eyes_manifest_falls_back_for_localhost_and_keeps_public_health_monitor() {
        let mut state = state::test_support::lazy_test_state();
        let registry = cron::registry();

        state.config.base_url = "http://localhost:3000".to_string();
        let local = eyes_boot_manifest(&state, &registry);
        assert_eq!(local.base_url, None);
        assert_eq!(local.monitors, None);
        assert_eq!(local.jobs.len(), 2);
        assert_eq!(local.crons.len(), 2);

        state.config.base_url = "https://prn.test".to_string();
        let public = eyes_boot_manifest(&state, &registry);
        assert_eq!(public.base_url.as_deref(), Some("https://prn.test"));
        let monitors = public.monitors.expect("public URL should keep its monitor");
        assert_eq!(monitors.len(), 1);
        assert_eq!(monitors[0].id, "health");
        assert_eq!(monitors[0].target, "https://prn.test/healthz");
        assert_eq!(public.jobs, local.jobs);
        assert_eq!(public.crons.len(), local.crons.len());
    }
}
