//! Discovery tools: `hosts`, `ping`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::*, schemars, tool,
    tool_router,
};
use serde::Deserialize;

use crate::output::Toon;
use crate::server::SshServer;
use crate::tools::{auth_str, text};

#[derive(Deserialize, schemars::JsonSchema)]
pub struct OptHostArgs {
    /// Host alias. Omit to query all configured hosts.
    #[serde(default)]
    pub host: Option<String>,
    /// Password for password-auth hosts. Cached after first successful connect. Ignored when targeting all hosts.
    #[serde(default)]
    pub password: Option<String>,
}

#[tool_router(router = discovery_router, vis = "pub")]
impl SshServer {
    #[tool(
        description = "List configured hosts with session state. Run this first to discover targets.",
        annotations(
            title = "Hosts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn hosts(&self) -> Result<CallToolResult, McpError> {
        let mut t = Toon::new();
        let cfg = self.cfg();
        let names = cfg.host_names();
        if names.is_empty() {
            t.field("hosts", "none configured");
            // The config file the server actually read, not the audit log's
            // directory: those are the same path only by default, and pointing
            // someone at the wrong file is worse than pointing at none.
            t.hint(&format!("edit {} to add hosts", self.config_path.display()));
            return Ok(text(t.into_string()));
        }
        let active = self.pool.list_active();
        let rows: Vec<Vec<String>> = names
            .iter()
            .filter_map(|n| {
                let h = cfg.hosts.get(n)?;
                let session = if active.contains(n) { "live" } else { "idle" };
                Some(vec![
                    n.clone(),
                    h.addr.clone(),
                    h.user.clone(),
                    h.port.to_string(),
                    auth_str(h.auth).into(),
                    session.into(),
                ])
            })
            .collect();
        t.table_strs(
            "hosts",
            &["name", "addr", "user", "port", "auth", "session"],
            &rows,
        );
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "TCP+SSH+auth liveness probe. Use to verify reachability before exec/sftp. With host probes one; without args probes all in parallel. Password arg only honored when host is specified.",
        annotations(
            title = "Ping",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn ping(
        &self,
        Parameters(args): Parameters<OptHostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let (targets, password): (Vec<String>, Option<zeroize::Zeroizing<String>>) = match args.host
        {
            Some(h) => (vec![h], args.password.map(zeroize::Zeroizing::new)),
            None => (self.cfg().host_names(), None),
        };
        let mut handles = Vec::new();
        for name in targets {
            let pool = self.pool.clone();
            let pw = password.clone();
            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let res = pool.get_or_connect(&name, pw.clone()).await;
                let elapsed = start.elapsed().as_millis() as u64;
                match res {
                    Ok(_) => {
                        if let Some(p) = pw {
                            pool.cache_password(&name, p);
                        }
                        (name, "ok".to_string(), elapsed, None)
                    }
                    Err(e) => (name, "fail".to_string(), elapsed, Some(e.to_string())),
                }
            }));
        }
        let mut rows = Vec::new();
        for h in handles {
            if let Ok((name, status, ms, err)) = h.await {
                rows.push(vec![
                    name,
                    status,
                    ms.to_string(),
                    err.unwrap_or_else(|| "-".into()),
                ]);
            }
        }
        let mut t = Toon::new();
        t.table_strs("ping", &["host", "status", "ms", "error"], &rows);
        Ok(text(t.into_string()))
    }
}
