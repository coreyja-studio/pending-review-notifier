use std::time::Duration;

use cja::{
    color_eyre::eyre::eyre,
    jobs::{CancellationToken, DEFAULT_LOCK_TIMEOUT, DEFAULT_MAX_RETRIES, worker::job_worker},
    setup::{setup_sentry, setup_tracing},
};
use tokio::task::JoinError;

mod cron;
mod crypto;
mod discovery;
mod github;
mod jobs;
mod routes;
mod session;
mod state;

use state::AppState;

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
    setup_tracing("prn")?;

    let app_state = AppState::from_env().await?;

    // Cancelled on SIGINT/SIGTERM; the job and cron workers watch it for
    // graceful shutdown.
    let shutdown_token = CancellationToken::new();
    tokio::spawn(cancel_on_shutdown_signal(shutdown_token.clone()));

    let router = routes::routes().with_state(app_state.clone());

    tracing::info!("Spawning tasks");
    let mut server = tokio::spawn(cja::server::run_server(router));
    let mut job = tokio::spawn(job_worker(
        app_state.clone(),
        jobs::Jobs,
        Duration::from_secs(5),
        DEFAULT_MAX_RETRIES,
        shutdown_token.clone(),
        DEFAULT_LOCK_TIMEOUT,
    ));
    let mut cron = tokio::spawn(cron::run_cron(app_state.clone(), shutdown_token.clone()));

    // Wait for a shutdown signal, or for any task to exit on its own —
    // these are long-running tasks, so an unprompted exit is an error.
    tokio::select! {
        () = shutdown_token.cancelled() => {}
        result = &mut server => return task_exited("server", result),
        result = &mut job => return task_exited("job_worker", result),
        result = &mut cron => return task_exited("cron_worker", result),
    }

    // Graceful shutdown: the job and cron workers watch the token and run
    // cleanup after their loops exit (the job worker's cleanup_worker_locks
    // releases its job locks so an in-flight job doesn't strand until the 2h
    // lock timeout on every deploy). Wait for them with a deadline that fits
    // under fly.toml's 10s kill_timeout.
    tracing::info!("Shutdown requested; waiting for workers to finish cleanup");
    // run_server doesn't watch the token and never exits on its own.
    server.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    for (name, handle) in [("job_worker", job), ("cron_worker", cron)] {
        match tokio::time::timeout_at(deadline, handle).await {
            Ok(Ok(Ok(()))) => tracing::info!(task = name, "Shut down cleanly"),
            Ok(Ok(Err(error))) => {
                tracing::error!(task = name, ?error, "Task errored during shutdown");
            }
            Ok(Err(join_error)) => {
                tracing::error!(task = name, ?join_error, "Task panicked during shutdown");
            }
            Err(_elapsed) => {
                tracing::warn!(
                    task = name,
                    "Task did not finish cleanup before the timeout"
                );
            }
        }
    }

    tracing::info!("Shutdown complete");
    Ok(())
}

/// A long-running task exited without a shutdown having been requested;
/// convert whatever happened into an error so the process restarts.
fn task_exited(name: &'static str, result: Result<cja::Result<()>, JoinError>) -> cja::Result<()> {
    match result {
        Ok(Ok(())) => {
            tracing::error!(task = name, "Task exited unexpectedly");
            Err(eyre!("Task '{name}' exited unexpectedly"))
        }
        Ok(Err(error)) => {
            tracing::error!(task = name, ?error, "Task failed");
            Err(error)
        }
        Err(join_error) => {
            tracing::error!(task = name, ?join_error, "Task panicked");
            Err(eyre!("Task '{name}' panicked: {join_error}"))
        }
    }
}

async fn cancel_on_shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install ctrl-c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("Shutdown signal received");
    token.cancel();
}
