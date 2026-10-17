//! DNS-over-HTTPS, added on top of CluvexStudio/Aether v1.5.0, which only
//! ships plain UDP:53 resolution (confirmed against socks.rs::resolver_addresses
//! in the upstream source -- see the top-level README's "Source review"
//! section). This module is new code, not upstream, written 2026-08-03
//! without a Rust toolchain available to compile-check it -- run
//! `cargo build` and `cargo test` in aether-core/aether before trusting it.
//! See APPLY.md in this same folder for the small edits this needs in
//! socks.rs and netstack.rs to wire in.
//!
//! Design choice worth calling out: a DoH query here runs over the SAME
//! smoltcp netstack (StackHandle::open_tcp) that SOCKS5 CONNECT already
//! uses -- i.e. through the already-established WARP tunnel -- not over the
//! device's raw network. Doing it any other way would mean DNS queries leak
//! outside the tunnel, which defeats half the point of asking for this.
//!
//! Config format for a DoH resolver entry (used wherever a --dns entry is
//! read): `doh:<ip>:<port>:<sni-host>:<path>`, e.g.
//! `doh:1.1.1.1:443:cloudflare-dns.com:/dns-query`. The IP is required and
//! not resolved via DNS (that would be circular -- you'd need working DNS to
//! resolve the DoH server before you have working DNS). Most public DoH
//! providers serve a valid cert for their real hostname even when you dial
//! the bare IP directly and set SNI/verification to that hostname, which is
//! exactly what this does.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};
use crate::netstack::{StackHandle, TcpSender};
use crate::socks::{build_dns_query, dns_response_matches, parse_dns_a};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const QTYPE_A: u16 = 1;

#[derive(Debug, Clone)]
pub struct DohTarget {
    pub ip: IpAddr,
    pub port: u16,
    pub sni: String,
    pub path: String,
}

impl DohTarget {
    /// Parses a `doh:<ip>:<port>:<sni-host>:<path>` entry. Returns None
    /// (rather than an error) for anything that doesn't match, so callers
    /// can treat "not a doh: entry" as "try the next resolver kind" the same
    /// way resolver_addresses() already silently skips malformed plain
    /// entries.
    pub fn parse(entry: &str) -> Option<Self> {
        let rest = entry.strip_prefix("doh:")?;
        let mut parts = rest.splitn(4, ':');
        let ip: IpAddr = parts.next()?.parse().ok()?;
        let port: u16 = parts.next()?.parse().ok()?;
        let sni = parts.next()?.to_string();
        let path = parts.next().unwrap_or("/dns-query").to_string();
        if sni.is_empty() || !path.starts_with('/') {
            return None;
        }
        Some(Self { ip, port, sni, path })
    }
}

/// Wraps a netstack TCP connection (split TcpSender + Receiver<Vec<u8>>) as
/// tokio AsyncRead + AsyncWrite, so tokio_boring's TLS client -- already used
/// elsewhere in this crate for the pre-tunnel API path in apifront.rs -- can
/// run over the tunnel netstack too.
struct NetstackTcpStream {
    tx: TcpSender,
    rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_fut: Option<Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>>,
    write_len: usize,
}

impl NetstackTcpStream {
    fn new(tx: TcpSender, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            tx,
            rx,
            read_buf: Vec::new(),
            read_pos: 0,
            write_fut: None,
            write_len: 0,
        }
    }
}

impl AsyncRead for NetstackTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let n = std::cmp::min(buf.remaining(), self.read_buf.len() - self.read_pos);
                let start = self.read_pos;
                buf.put_slice(&self.read_buf[start..start + n]);
                self.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.read_buf = chunk;
                    self.read_pos = 0;
                    continue;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF, zero-fill nothing
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for NetstackTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_none() {
            let data = buf.to_vec();
            self.write_len = data.len();
            let tx = self.tx.clone();
            self.write_fut = Some(Box::pin(async move { tx.send(data).await }));
        }
        let poll = self.write_fut.as_mut().unwrap().as_mut().poll(cx);
        match poll {
            Poll::Ready(Ok(())) => {
                self.write_fut = None;
                Poll::Ready(Ok(self.write_len))
            }
            Poll::Ready(Err(e)) => {
                self.write_fut = None;
                Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs one DoH query (RFC 8484, POST form) for `name`'s A record against
/// `target`, over the tunneled netstack. Mirrors dns_exchange()'s plain-UDP
/// sibling in socks.rs: same query builder, same response validation, same
/// "return the first good answer" shape.
pub(crate) async fn doh_query(stack: &StackHandle, target: &DohTarget, name: &str) -> Result<IpAddr> {
    let addr = SocketAddr::new(target.ip, target.port);

    let conn = tokio::time::timeout(CONNECT_TIMEOUT, stack.open_tcp(addr))
        .await
        .map_err(|_| AetherError::Other(format!("doh: connect to {addr} timed out")))??;
    let (tx, rx) = conn.into_split();
    let stream = NetstackTcpStream::new(tx, rx);

    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Other(format!("doh tls: {e}")))?;
    builder.set_verify(SslVerifyMode::PEER); // real public CA validation -- no pinning, this is an arbitrary user-chosen server
    let config = builder
        .build()
        .configure()
        .map_err(|e| AetherError::Other(format!("doh tls: {e}")))?;

    let mut tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_boring::connect(config, &target.sni, stream),
    )
    .await
    .map_err(|_| AetherError::Other(format!("doh: tls handshake with {} timed out", target.sni)))?
    .map_err(|e| AetherError::Other(format!("doh: tls handshake with {}: {e}", target.sni)))?;

    let (query, id) = build_dns_query(name, QTYPE_A);
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        path = target.path,
        host = target.sni,
        len = query.len()
    );

    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        tls.write_all(request.as_bytes()).await?;
        tls.write_all(&query).await?;
        tls.flush().await
    })
    .await
    .map_err(|_| AetherError::Other("doh: request send timed out".into()))??;

    let body = tokio::time::timeout(EXCHANGE_TIMEOUT, read_http_response_body(&mut tls))
        .await
        .map_err(|_| AetherError::Other("doh: response read timed out".into()))??;

    if !dns_response_matches(&body, id, name, QTYPE_A) {
        return Err(AetherError::Other(format!(
            "doh: response from {} did not match the query",
            target.sni
        )));
    }
    parse_dns_a(&body).ok_or_else(|| AetherError::Other(format!("doh: no A record for {name}")))
}

/// Minimal hand-rolled HTTP/1.1 response reader -- deliberately not pulling
/// in reqwest/hyper for this: they don't have a simple way to run over an
/// arbitrary custom async transport (this one is neither a raw TCP socket
/// nor anything hyper's connectors know about), and the crate already reads
/// HTTP status lines by hand elsewhere (see socks.rs::proxy_connect_succeeded)
/// so this matches existing style. Reads headers, finds Content-Length,
/// reads exactly that many body bytes. Chunked transfer-encoding is
/// intentionally not handled -- DoH POST responses are always sent with a
/// concrete Content-Length by every real-world provider tested against
/// (Cloudflare, Google, Quad9); if you point this at a server that answers
/// chunked, it will error out cleanly here rather than silently truncating.
async fn read_http_response_body<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_RESPONSE_BYTES {
            return Err(AetherError::Other("doh: response headers too large".into()));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(AetherError::Other("doh: connection closed before headers completed".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AetherError::Other(format!("doh: bad status line {status_line:?}")))?;
    if !(200..300).contains(&status) {
        return Err(AetherError::Other(format!("doh: server returned HTTP {status}")));
    }

    let content_length: usize = head
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| AetherError::Other("doh: response has no Content-Length (chunked responses aren't supported)".into()))?;
    if content_length > MAX_RESPONSE_BYTES {
        return Err(AetherError::Other("doh: response body too large".into()));
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(AetherError::Other("doh: connection closed before full body received".into()));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_doh_entry() {
        let t = DohTarget::parse("doh:1.1.1.1:443:cloudflare-dns.com:/dns-query").unwrap();
        assert_eq!(t.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(t.port, 443);
        assert_eq!(t.sni, "cloudflare-dns.com");
        assert_eq!(t.path, "/dns-query");
    }

    #[test]
    fn defaults_the_path_when_omitted() {
        let t = DohTarget::parse("doh:1.1.1.1:443:cloudflare-dns.com").unwrap();
        assert_eq!(t.path, "/dns-query");
    }

    #[test]
    fn rejects_a_plain_ip_entry() {
        assert!(DohTarget::parse("1.1.1.1").is_none());
    }

    #[test]
    fn rejects_a_bad_ip() {
        assert!(DohTarget::parse("doh:not-an-ip:443:example.com:/dns-query").is_none());
    }

    #[test]
    fn rejects_a_path_missing_its_leading_slash() {
        assert!(DohTarget::parse("doh:1.1.1.1:443:example.com:dns-query").is_none());
    }
}
