> **STATUS (core v2.3.0): NOT APPLIED, NOT VERIFIED.** This patch was written
> against Aether v1.5.0's `socks.rs`/`netstack.rs`. The app now builds core
> v2.3.0, whose source I have not read, so the find/replace blocks below may
> no longer match and the patch is deliberately NOT part of the CI build.
> If you still want DoH, say so and I will re-derive it against the v2.3.0
> source first rather than apply this blind.

# Wiring in DoH support

Five small, exact edits on top of the real v1.5.0 source (all locations
confirmed by reading the actual file, not guessed). Do them in this order,
then `cargo build` and `cargo test` before trusting any of it — none of this
has been compiled, since this sandbox has no Rust toolchain.

## 1. Drop in the new file

Copy `doh.rs` (next to this file) to `aether/src/doh.rs`.

## 2. `aether/src/main.rs` — register the module

Find:
```rust
mod dns;
mod error;
```
Replace with:
```rust
mod dns;
mod doh;
mod error;
```
(Alphabetical, matching the existing style — insert wherever keeps it sorted if the surrounding lines differ by the time you apply this.)

## 3. `aether/src/netstack.rs` — make TcpSender cloneable

Find:
```rust
pub struct TcpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}
```
Replace with:
```rust
#[derive(Clone)]
pub struct TcpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}
```
Safe by construction: it's just a usize + an `mpsc::Sender` (itself `Clone`
by design — cloning a sender doesn't duplicate the connection, it just gives
you another handle to push into the same channel, exactly like `UdpSender`
conceptually already allows via its own `data_in`).

## 4. `aether/src/socks.rs` — two visibility bumps

Find:
```rust
fn build_dns_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
```
Replace with:
```rust
pub(crate) fn build_dns_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
```

Find:
```rust
fn parse_dns_a(resp: &[u8]) -> Option<IpAddr> {
```
Replace with:
```rust
pub(crate) fn parse_dns_a(resp: &[u8]) -> Option<IpAddr> {
```

## 5. `aether/src/socks.rs` — the actual resolver logic

Find:
```rust
pub(crate) fn resolver_addresses() -> Vec<SocketAddr> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut servers: Vec<SocketAddr> = Vec::new();

    for token in configured.split([',', ' ', ';']) {
        let entry = token.trim();
        if entry.is_empty() {
            continue;
        }
        let parsed = entry.parse::<SocketAddr>().ok().or_else(|| {
            entry
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        });
        if let Some(server) = parsed {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }

    if servers.is_empty() {
        servers.push("1.1.1.1:53".parse().unwrap());
        servers.push("1.0.0.1:53".parse().unwrap());
    }
    servers
}
```

Replace with:
```rust
pub(crate) enum Resolver {
    Plain(SocketAddr),
    Doh(crate::doh::DohTarget),
}

pub(crate) fn resolver_addresses() -> Vec<Resolver> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut servers: Vec<Resolver> = Vec::new();

    for token in configured.split([',', ' ', ';']) {
        let entry = token.trim();
        if entry.is_empty() {
            continue;
        }
        // doh:<ip>:<port>:<sni-host>:<path> -- checked first since it has
        // its own "doh:" prefix and can never be confused with a plain
        // ip/ip:port entry.
        if let Some(doh) = crate::doh::DohTarget::parse(entry) {
            servers.push(Resolver::Doh(doh));
            continue;
        }
        let parsed = entry.parse::<SocketAddr>().ok().or_else(|| {
            entry
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        });
        if let Some(server) = parsed {
            let dup = servers
                .iter()
                .any(|s| matches!(s, Resolver::Plain(p) if *p == server));
            if !dup {
                servers.push(Resolver::Plain(server));
            }
        }
    }

    if servers.is_empty() {
        servers.push(Resolver::Plain("1.1.1.1:53".parse().unwrap()));
        servers.push(Resolver::Plain("1.0.0.1:53".parse().unwrap()));
    }
    servers
}
```

Then find:
```rust
pub(crate) async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();
    let outcome = dns_exchange(&sender, &mut from_stack, name).await;
    sender.close().await;
    outcome
}
```
Replace with:
```rust
pub(crate) async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();
    let outcome = dns_exchange(stack, &sender, &mut from_stack, name).await;
    sender.close().await;
    outcome
}
```
(Just threading `stack` through so the function below can open a TCP
connection for DoH entries, not only UDP.)

Then find:
```rust
async fn dns_exchange(
    sender: &UdpSender,
    from_stack: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    name: &str,
) -> Result<IpAddr> {
    let mut last = AetherError::Other("dns timeout".into());

    for server in resolver_addresses() {
        let (query, id) = build_dns_query(name, QTYPE_A);
        if let Err(error) = sender.send_to(server, query).await {
            last = error;
            continue;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        loop {
            let resp = match tokio::time::timeout_at(deadline, from_stack.recv()).await {
                Ok(Some(resp)) => resp,
                Ok(None) => return Err(AetherError::Other("dns channel closed".into())),
                Err(_) => {
                    last = AetherError::Other(format!("dns timeout from {server}"));
                    break;
                }
            };

            if !dns_response_matches(&resp.1, id, name, QTYPE_A) {
                continue;
            }
            if let Some(ip) = parse_dns_a(&resp.1) {
                return Ok(ip);
            }
            return Err(AetherError::Other(format!("no A record for {name}")));
        }
    }

    Err(last)
}
```

Replace with:
```rust
async fn dns_exchange(
    stack: &StackHandle,
    sender: &UdpSender,
    from_stack: &mut mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    name: &str,
) -> Result<IpAddr> {
    let mut last = AetherError::Other("dns timeout".into());

    for resolver in resolver_addresses() {
        match resolver {
            Resolver::Doh(target) => match crate::doh::doh_query(stack, &target, name).await {
                Ok(ip) => return Ok(ip),
                Err(error) => {
                    last = error;
                    continue;
                }
            },
            Resolver::Plain(server) => {
                let (query, id) = build_dns_query(name, QTYPE_A);
                if let Err(error) = sender.send_to(server, query).await {
                    last = error;
                    continue;
                }

                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

                loop {
                    let resp = match tokio::time::timeout_at(deadline, from_stack.recv()).await {
                        Ok(Some(resp)) => resp,
                        Ok(None) => return Err(AetherError::Other("dns channel closed".into())),
                        Err(_) => {
                            last = AetherError::Other(format!("dns timeout from {server}"));
                            break;
                        }
                    };

                    if !dns_response_matches(&resp.1, id, name, QTYPE_A) {
                        continue;
                    }
                    if let Some(ip) = parse_dns_a(&resp.1) {
                        return Ok(ip);
                    }
                    return Err(AetherError::Other(format!("no A record for {name}")));
                }
            }
        }
    }

    Err(last)
}
```

## After applying

```
cd native/aether-core/aether
cargo build
cargo test doh::
```

The `cargo test doh::` run only exercises `DohTarget::parse` (pure, no
network) — it won't tell you whether an actual DoH exchange against a real
server works, only that the format parsing is right. For that, run the
engine with e.g. `AETHER_DNS=doh:1.1.1.1:443:cloudflare-dns.com:/dns-query`
against a real network and watch the SOCKS5 log for resolution errors.

## What this does not do

- No connection pooling / keep-alive — every query opens a fresh TCP+TLS
  connection. Fine for the request rate a personal client generates; would
  need work before it'd be reasonable for anything higher-volume.
- No DoH3/DNS-over-QUIC — that's a materially bigger addition (would want to
  reuse the crate's existing `quiche`-based QUIC/H3 stack from `masque_h2.rs`/
  `quic.rs` rather than hand-rolling a second QUIC client), not attempted
  here. Ask if you want that added too, but expect it to be a larger patch
  than this one.
- Chunked transfer-encoding responses aren't handled (see the comment on
  `read_http_response_body` in doh.rs) — not an issue for the major public
  DoH providers, which all send Content-Length.
