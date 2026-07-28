//! Operational tools. Empty for now; the router is wired so tools can land
//! here without touching `SshServer::tool_router`.

use rmcp::tool_router;

use crate::server::SshServer;

#[tool_router(router = ops_router, vis = "pub")]
impl SshServer {}
