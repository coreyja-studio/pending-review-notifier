use std::time::Duration;

use cja::{
    jobs::{CancellationToken, DEFAULT_LOCK_TIMEOUT, DEFAULT_MAX_RETRIES, worker::job_worker},
    setup::{setup_sentry, setup_tracing},
    tasks::{NamedTask, wait_for_first_error},
};

mod cron;
mod jobs;
mod routes;
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
    let tasks = vec![
        NamedTask::spawn("server", cja::server::run_server(router)),
        NamedTask::spawn(
            "job_worker",
            job_worker(
                app_state.clone(),
                jobs::Jobs,
                Duration::from_secs(5),
                DEFAULT_MAX_RETRIES,
                shutdown_token.clone(),
                DEFAULT_LOCK_TIMEOUT,
            ),
        ),
        NamedTask::spawn(
            "cron_worker",
            cron::run_cron(app_state.clone(), shutdown_token.clone()),
        ),
    ];

    tokio::select! {
        result = wait_for_first_error(tasks) => result,
        () = shutdown_token.cancelled() => {
            tracing::info!("Shutdown requested, exiting");
            Ok(())
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
