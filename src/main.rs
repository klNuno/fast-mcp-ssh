// Anything written to stdout outside of the rmcp transport corrupts the MCP
// JSON-RPC framing — the client silently disconnects. These deny lints make
// the build fail before that happens. Set on both targets: the lib carries its
// own copy, a crate-level attribute does not cross the lib/bin boundary.
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::{EnvFilter, fmt};

use fast_mcp_ssh::audit::{self, AuditLog};
use fast_mcp_ssh::config::{Config, default_config_path};
use fast_mcp_ssh::guards::GuardCache;
use fast_mcp_ssh::server::SshServer;
use fast_mcp_ssh::session::SessionPool;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(clap::Parser, Debug)]
#[command(name = "fast-mcp-ssh", version, about = "Fast MCP SSH server")]
struct Cli {
    /// Path to hosts.toml. Defaults to $FAST_MCP_SSH_HOME or ~/.fast-mcp-ssh/hosts.toml.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Parse and validate the config without starting the server. Exits non-zero
    /// on any validation failure.
    Check,
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let ansi = std::io::stderr().is_terminal();
    // Non-blocking writer: if the MCP host never drains our stderr pipe, a
    // synchronous writer would eventually block the single runtime thread on
    // a full pipe buffer and freeze every in-flight call. The appender drops
    // log lines instead. The guard must live for the whole process.
    let (stderr_writer, _stderr_guard) = tracing_appender::non_blocking(std::io::stderr());
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fast_mcp_ssh=info,russh=warn")),
        )
        .with_writer(stderr_writer)
        .with_ansi(ansi)
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
    let cfg_swap = Arc::new(ArcSwap::from_pointee(cfg));

    if matches!(cli.command, Some(Command::Check)) {
        let cfg = cfg_swap.load();
        tracing::info!(
            hosts = cfg.hosts.len(),
            config = %cfg_path.display(),
            "config OK"
        );
        return Ok(());
    }

    let (audit_path, audit_rotation) = {
        let cfg = cfg_swap.load();
        let path = if cfg.defaults.audit_log {
            Some(cfg.defaults.audit_log_path.clone())
        } else {
            None
        };
        (
            path,
            audit::AuditRotation {
                max_bytes: cfg.defaults.audit_max_bytes,
                keep_files: cfg.defaults.audit_keep_files,
            },
        )
    };
    let audit = Arc::new(AuditLog::new(audit_path, audit_rotation)?);
    let pool = SessionPool::new(cfg_swap.clone())?;
    let guards_swap = Arc::new(ArcSwap::from_pointee(GuardCache::build(&cfg_swap.load())?));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let pool_for_evict = pool.clone();
    let mut evict_rx = shutdown_rx.clone();
    // Tick at most once per minute, and at least twice per idle window so
    // sessions don't linger past `session_idle_timeout` by up to a minute on
    // short timeouts.
    let evict_interval = std::cmp::max(
        std::time::Duration::from_secs(5),
        std::cmp::min(
            std::time::Duration::from_secs(60),
            cfg_swap.load().defaults.session_idle_timeout.0 / 2,
        ),
    );
    let evict_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(evict_interval) => {
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
        hosts = cfg_swap.load().hosts.len(),
        config = %cfg_path.display(),
        "fast-mcp-ssh starting"
    );

    let server = SshServer::new(
        cfg_swap.clone(),
        pool,
        audit.clone(),
        guards_swap,
        cfg_path.clone(),
    );
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
