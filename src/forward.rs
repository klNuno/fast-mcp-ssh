//! Local TCP -> remote TCP port forwarding tunneled through an SSH session.
//!
//! `start()` binds a `127.0.0.1:<local_port>` listener and, for each
//! accepted connection, opens an SSH `direct-tcpip` channel and proxies
//! bytes in both directions until either side closes. The returned
//! `ForwardHandle` aborts the listener (and thereby any new accepts) when
//! `stop()` is called. In-flight connections are left to drain naturally so
//! the user doesn't get a hard RST mid-transfer.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::{AbortHandle, JoinHandle};

use crate::errors::{Result, SshError};
use crate::session::Session;

pub struct ForwardHandle {
    pub host_alias: String,
    #[allow(dead_code)]
    pub local_port: u16,
    pub bound_addr: SocketAddr,
    pub remote_host: String,
    pub remote_port: u16,
    abort: AbortHandle,
}

impl ForwardHandle {
    pub fn stop(self) {
        self.abort.abort();
    }
}

pub async fn start(
    session: Arc<Session>,
    host_alias: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<ForwardHandle> {
    let bind = format!("127.0.0.1:{local_port}");
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| SshError::Other(format!("bind {bind}: {e}")))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| SshError::Other(format!("local_addr: {e}")))?;

    let session_for_task = Arc::clone(&session);
    let remote_host_for_task = remote_host.clone();
    let join: JoinHandle<()> = tokio::spawn(async move {
        loop {
            let (mut socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "forward listener accept failed");
                    break;
                }
            };
            let _ = socket.set_nodelay(true);
            let session_for_conn = Arc::clone(&session_for_task);
            let remote_host_for_conn = remote_host_for_task.clone();
            tokio::spawn(async move {
                let channel = match session_for_conn
                    .handle
                    .channel_open_direct_tcpip(
                        remote_host_for_conn.clone(),
                        remote_port as u32,
                        peer.ip().to_string(),
                        peer.port() as u32,
                    )
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(?e, %peer, "direct-tcpip open failed");
                        let _ = socket.shutdown().await;
                        return;
                    }
                };
                let mut stream = channel.into_stream();
                if let Err(e) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
                    tracing::debug!(?e, %peer, "forward copy ended");
                }
            });
        }
    });

    Ok(ForwardHandle {
        host_alias,
        local_port,
        bound_addr,
        remote_host,
        remote_port,
        abort: join.abort_handle(),
    })
}
