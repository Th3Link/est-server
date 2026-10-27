//! Running the server until it is told to stop.

use std::future::Future;

use crate::config::Config;

/// Start the server from `config` and serve until `shutdown` completes.
/// Everything the server started is stopped when this returns.
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let running = crate::app::start(&config).await?;
    tokio::select! {
        _ = running.wait() => anyhow::bail!("a listener stopped"),
        _ = shutdown => {}
    }
    tracing::info!("shutting down");
    Ok(())
}
