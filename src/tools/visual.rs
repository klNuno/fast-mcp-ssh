//! Visual/rendering tools. Empty for now; the router is wired so tools can
//! land here without touching `SshServer::tool_router`.

use rmcp::tool_router;

use crate::server::SshServer;

#[tool_router(router = visual_router, vis = "pub")]
impl SshServer {}
