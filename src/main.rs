use std::time::Duration;

use cja::{
    jobs::{DEFAULT_LOCK_TIMEOUT, DEFAULT_MAX_RETRIES, worker::job_worker_with_shutdown_drain},
    server::run_server_until,
    setup::{setup_sentry, setup_tracing},
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
/// `kill_timeout = "10s"`: 8s in total, leaving ~2s before SIGKILL for the
/// process to exit and telemetry to flush.
///
/// An in-flight job gets 5s to finish. `SyncUser` and `SendReminder` are a
/// handful of GitHub/MailPace round trips, so that lets nearly all of them
/// complete instead of being re-run (a `SendReminder` dropped between the
/// send and the `notified_at` stamp re-sends the email on retry). Whatever is
/// still running after 5s is dropped with its lock released, so the next
/// boot claims it at once rather than after the 2h lock timeout. The
/// remaining 3s covers that lock release, the cron worker, and the HTTP
/// server closing its connections.
const SHUTDOWN_BUDGET: ShutdownBudget = ShutdownBudget {
    job_drain: Duration::from_secs(5),
    exit_grace: Duration::from_secs(3),
};

fn main() -> cja::Result<()> {
    color_eyre::install()?;

    // Sentry must be initialized before the tokio runtime starts.
    let _sentry_guard = setup_sentry();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> cja::Result<()> {
    // Keep the eyes shutdown handle alive for the life of the process:
    // dropping it stops eyes-subscriber's transport loop, which would
    // silently disable eyes telemetry (enabled via EYES_ORG_ID/EYES_APP_ID).
    let _eyes_shutdown_handle = setup_tracing("prn")?;

    let app_state = AppState::from_env().await?;

    // Build the cron registry once so it can seed the Eyes boot manifest
    // before being handed off to the cron worker.
    let cron_registry = cron::registry();

    // The existing public health endpoint also gives Eyes an external check
    // of this always-on service. Keep boot registration best effort.
    let manifest = cja::eyes_manifest::build_boot_manifest::<jobs::Jobs, AppState>(
        Some(env!("CARGO_PKG_VERSION")),
        None,
        Some(&cron_registry),
    )
    .base_url(app_state.config.base_url.clone())
    .monitors(vec![cja::eyes_manifest::HttpMonitor::new(
        "health", "/healthz",
    )]);
    cja::eyes_manifest::send_manifest(manifest);

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
        job_worker_with_shutdown_drain(
            app_state.clone(),
            jobs::Jobs,
            Duration::from_secs(5),
            DEFAULT_MAX_RETRIES,
            shutdown.clone(),
            DEFAULT_LOCK_TIMEOUT,
            supervisor.budget().job_drain,
        ),
    );
    supervisor.spawn(
        "cron_worker",
        cron::run_cron(app_state, cron_registry, shutdown),
    );

    supervisor.run().await
}
