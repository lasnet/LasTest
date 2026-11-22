//! LasTest library: shared domain, API, worker and CLI support.

pub mod api;
pub mod auth;
pub mod cli;
pub mod config;
pub mod db;
pub mod domain;
pub mod import;
pub mod net;
mod provider_settings;
pub mod report;
pub mod scope;
pub mod tasks;
pub mod worker;

use anyhow::Result;
use std::sync::Arc;

pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn serve(config: config::Config) -> Result<()> {
    config.ensure_dirs()?;
    let db = db::Db::new(config.database_path())?;
    let state = Arc::new(api::AppState::new(config.clone(), db));
    let address: std::net::SocketAddr = config.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "LasTest API listening");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            wait_for_shutdown_signal().await;
            tracing::info!("API shutdown signal received");
        })
        .await?;
    Ok(())
}
