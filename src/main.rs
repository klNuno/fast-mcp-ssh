mod audit;
mod config;
mod errors;
mod guards;
mod known_hosts;
mod output;
mod server;
mod session;
mod sftp;
mod tail;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use mimalloc::MiMalloc;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::AuditLog;
use crate::config::{Config, default_config_path};
use crate::guards::GuardCache;
use crate::server::SshServer;
use crate::session::SessionPool;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(clap::Parser, Debug)]
#[command(name = "fast-mcp-ssh", version, about = "Fast MCP SSH server")]
struct Cli {
    /// Path to hosts.toml. Defaults to $FAST_MCP_SSH_HOME or ~/.fast-mcp-ssh/hosts.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fast_mcp_ssh=debug,russh=warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    let cfg_path = cli.config.unwrap_or_else(default_config_path);
    let cfg = match Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(?e, path = %cfg_path.display(), "config load failed");
            return Err(anyhow::anyhow!("{e}"));
        }
    };
    let cfg = Arc::new(cfg);

    let audit_path = if cfg.defaults.audit_log {
        Some(cfg.defaults.audit_log_path.clone())
    } else {
        None
    };
    let audit = Arc::new(AuditLog::new(audit_path)?);
    let pool = SessionPool::new(cfg.clone())?;
    let guards = Arc::new(GuardCache::build(&cfg)?);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let pool_for_evict = pool.clone();
    let mut evict_rx = shutdown_rx.clone();
    let evict_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    pool_for_evict.evict_idle().await;
                }
                res = evict_rx.changed() => {
                    if res.is_err() || *evict_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    tracing::info!(
        hosts = cfg.hosts.len(),
        config = %cfg_path.display(),
        "fast-mcp-ssh starting"
    );

    let server = SshServer::new(cfg.clone(), pool, audit.clone(), guards);
    let service = server.serve(stdio()).await?;
    let serve_result = service.waiting().await;

    // Graceful shutdown: stop background tasks, drain audit log to disk.
    let _ = shutdown_tx.send(true);
    let _ = shutdown_rx.changed().await;
    let _ = evict_handle.await;
    audit.shutdown().await;

    serve_result?;
    Ok(())
}
