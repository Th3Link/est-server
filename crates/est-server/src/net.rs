//! Listening sockets (dual-stack) and the TLS accept loop.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::peer::{ConnInfo, normalize};

/// Time for the TLS handshake. Small clients do it in software and
/// take a few seconds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Time for everything after the handshake on one connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Bind all addresses. An IPv6 wildcard serves IPv4 too (mapped
/// addresses) unless an IPv4 listener on the same port is configured,
/// in which case each family gets its own socket.
pub fn bind_all(addrs: &[SocketAddr]) -> anyhow::Result<Vec<TcpListener>> {
    addrs
        .iter()
        .map(|addr| {
            let v4_twin = addrs.iter().any(|o| o.is_ipv4() && o.port() == addr.port());
            bind(*addr, addr.is_ipv6() && v4_twin).with_context(|| format!("listen on {addr}"))
        })
        .collect()
}

fn bind(addr: SocketAddr, v6_only: bool) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    if addr.is_ipv6() {
        socket.set_only_v6(v6_only)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Serve EST over TLS on `listener` until the task is dropped. Every
/// request gets the connection's [`ConnInfo`] as an extension.
pub async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, router: Router) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let remote = normalize(remote);
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!(%remote, "TLS handshake failed: {e}");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%remote, "TLS handshake timed out");
                    return;
                }
            };
            let chain = tls
                .get_ref()
                .1
                .peer_certificates()
                .map(<[_]>::to_vec)
                .unwrap_or_default();
            let info = Arc::new(ConnInfo { remote, chain });
            let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(info.clone());
                let router = router.clone();
                async move {
                    match router.oneshot(req.map(axum::body::Body::new)).await {
                        Ok(response) => Ok::<_, Infallible>(response),
                        Err(never) => match never {},
                    }
                }
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            match tokio::time::timeout(CONNECTION_TIMEOUT, conn).await {
                Ok(Err(e)) => tracing::debug!(%remote, "connection: {e}"),
                Err(_) => tracing::debug!(%remote, "connection timed out"),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wildcard_v6_listener_takes_ipv4_too() {
        let listeners = bind_all(&["[::]:0".parse().unwrap()]).unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        for target in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
            let connect = tokio::net::TcpStream::connect(&target);
            let (accepted, connected) = tokio::join!(listeners[0].accept(), connect);
            let (_, remote) = accepted.unwrap();
            connected.unwrap();
            assert_eq!(
                normalize(remote).ip(),
                target.parse::<SocketAddr>().unwrap().ip()
            );
        }
    }
}
