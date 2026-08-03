//! Port-forwarding tools: `forward`, `forwards`, `unforward`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::*, schemars, tool,
    tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::errors::SshError;
use crate::forward;
use crate::output::Toon;
use crate::server::SshServer;
use crate::tools::text;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ForwardArgs {
    /// Host alias whose SSH session is used as the tunnel transport.
    #[serde(default)]
    pub host: Option<String>,
    /// Local TCP port to bind on 127.0.0.1. Must be free.
    pub local_port: u16,
    /// Remote host the SSH server should connect outbound to. Often
    /// `127.0.0.1` (services bound on the remote box) or a name visible from
    /// the remote box's network.
    pub remote_host: String,
    /// Remote TCP port.
    pub remote_port: u16,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UnforwardArgs {
    /// Local port to release.
    pub local_port: u16,
}

#[tool_router(router = net_router, vis = "pub")]
impl SshServer {
    #[tool(
        description = "Open local TCP forward: 127.0.0.1:<local_port> -> remote_host:remote_port via SSH. Returns once the listener is bound; tunnel lives in background until unforward.",
        annotations(
            title = "Forward",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn forward(
        &self,
        Parameters(args): Parameters<ForwardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if self.forwards.contains_key(&args.local_port) {
            return Err(SshError::Config(format!(
                "local port {} already forwarded; unforward first",
                args.local_port
            ))
            .into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let handle = forward::start(
            session,
            host_name.clone(),
            args.local_port,
            args.remote_host.clone(),
            args.remote_port,
        )
        .await
        .map_err(|e| e.into_mcp())?;
        let bound = handle.bound_addr;
        self.forwards.insert(args.local_port, handle);
        self.audit.write(
            &host_name,
            "forward",
            AuditRecord::cmd(&format!(
                "127.0.0.1:{} -> {}:{}",
                args.local_port, args.remote_host, args.remote_port
            )),
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("local", bound.to_string())
            .field(
                "remote",
                format!("{}:{}", args.remote_host, args.remote_port),
            )
            .field("status", "listening");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Stop a local forward by local port. Existing in-flight connections drain naturally.",
        annotations(
            title = "Unforward",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn unforward(
        &self,
        Parameters(args): Parameters<UnforwardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut t = Toon::new();
        t.field("local_port", args.local_port as u64);
        match self.forwards.remove(&args.local_port) {
            Some((_, handle)) => {
                let host = handle.host_alias.clone();
                handle.stop();
                self.audit.write(
                    &host,
                    "unforward",
                    AuditRecord::cmd(&format!("port={}", args.local_port)),
                );
                t.field("status", "stopped");
            }
            None => {
                t.field("status", "no such forward");
            }
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "List active local→remote forwards.",
        annotations(
            title = "Forwards",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn forwards(&self) -> Result<CallToolResult, McpError> {
        let rows: Vec<Vec<String>> = self
            .forwards
            .iter()
            .map(|e| {
                let h = e.value();
                vec![
                    h.host_alias.clone(),
                    h.bound_addr.to_string(),
                    format!("{}:{}", h.remote_host, h.remote_port),
                ]
            })
            .collect();
        let mut t = Toon::new();
        t.table_strs("forwards", &["host", "local", "remote"], &rows);
        Ok(text(t.into_string()))
    }
}
