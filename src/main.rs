mod audit;
mod config;
mod errors;
mod guards;
mod output;
mod server;
mod session;
mod sftp;
mod tail;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::AuditLog;
use crate::config::{Config, default_config_path};
use crate::server::SshServer;
use crate::session::SessionPool;

#[derive(clap::Parser, Debug)]
#[command(name = "fast-mcp-ssh", version, about = "Fast MCP SSH server")]
struct Cli {
    /// Path to hosts.toml. Defaults to $FAST_MCP_SSH_HOME or ~/.fast-mcp-ssh/hosts.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let pool = SessionPool::new(cfg.clone());

    let pool_for_evict = pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            pool_for_evict.evict_idle().await;
        }
    });

    tracing::info!(
        hosts = cfg.hosts.len(),
        config = %cfg_path.display(),
        "fast-mcp-ssh starting"
    );

    let server = SshServer::new(cfg.clone(), pool, audit);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
