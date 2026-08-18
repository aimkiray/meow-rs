mod firewall;
mod orig_dest;

use crate::sniffer::SnifferRuntime;
use firewall::FirewallGuard;
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

pub struct TProxyListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    routing_mark: Option<u32>,
    name: String,
}

impl TProxyListener {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        enable_sni: bool,
        routing_mark: Option<u32>,
        name: String,
    ) -> Self {
        // Deprecated `enable_sni` knob: synthesise a minimal sniffer config.
        let sniffer = if enable_sni {
            warn!(
                "`enable_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this release. \
                Will be removed in a future version."
            );
            let cfg = meow_common::SnifferConfig {
                enable: true,
                tls_ports: vec![443],
                http_ports: Vec::new(),
                ..Default::default()
            };
            Some(Arc::new(SnifferRuntime::new(cfg)))
        } else {
            None
        };
        Self {
            tunnel,
            listen_addr,
            sniffer,
            routing_mark,
            name,
        }
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Bind first so a port-0 listen can resolve to the OS-assigned port
        // before firewall rules are installed against it.
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Serve on an already-bound socket, letting the caller resolve a
    /// `port: 0` ephemeral listener to its OS-assigned port first. Firewall
    /// redirect rules are installed against the socket's actual local port,
    /// so ephemeral listeners redirect correctly.
    pub async fn run_on(
        self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect upstream proxy server IPs for firewall bypass
        let bypass_ips = collect_proxy_server_ips(&self.tunnel);

        let bound_addr = listener.local_addr().unwrap_or(self.listen_addr);

        // Set up firewall redirect rules (tears down on drop)
        let _firewall = FirewallGuard::setup(bound_addr.port(), self.routing_mark, &bypass_ips)?;

        info!("TProxy listener '{}' started on {}", self.name, bound_addr);

        // Scope decision for the pf path (#248): the managed ruleset
        // intercepts loopback-traversing IPv4 TCP only; steering real
        // outbound (en0) traffic stays a manual, documented pf detour rather
        // than something meow rewrites the host's pf config for. Surface that
        // at startup so "tproxy is on but my browser isn't proxied" is
        // explained by the log, not a silent surprise.
        #[cfg(target_os = "macos")]
        info!(
            "TProxy on macOS intercepts loopback IPv4 TCP only; real outbound \
             traffic needs the manual route-to detour (docs/tproxy-macos.md) — \
             for full transparent proxying use the TUN inbound (docs/tun.md)"
        );

        loop {
            let (stream, src_addr) = listener.accept().await?;
            let tunnel = self.tunnel.clone();
            let listen_addr = bound_addr;
            let sniffer = self.sniffer.clone();
            let name = self.name.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_tproxy_conn(tunnel, stream, src_addr, listen_addr, sniffer, name).await
                {
                    debug!("TProxy connection error from {src_addr}: {e}");
                }
            });
        }
    }
}

/// Collect all upstream proxy server IPs from the tunnel's proxy map.
/// These IPs must be excluded from firewall redirection to prevent loops.
fn collect_proxy_server_ips(tunnel: &Tunnel) -> Vec<IpAddr> {
    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let mut ips = HashSet::new();

    for proxy in proxies.values() {
        let addr_str = proxy.addr();
        if addr_str.is_empty() {
            continue;
        }

        // Try parsing as ip:port directly
        if let Ok(sock) = addr_str.parse::<SocketAddr>() {
            ips.insert(sock.ip());
            continue;
        }

        // Try parsing as just an IP
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            ips.insert(ip);
            continue;
        }

        // Try DNS resolution for host:port
        if let Ok(resolved) = addr_str.to_socket_addrs() {
            for sock in resolved {
                ips.insert(sock.ip());
            }
        }
    }

    let result: Vec<IpAddr> = ips.into_iter().collect();
    info!(
        "Collected {} upstream proxy IPs for firewall bypass: {:?}",
        result.len(),
        result
    );
    result
}

async fn handle_tproxy_conn(
    tunnel: Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Recover the original destination address
    let orig_dst = orig_dest::get_original_dst(&stream, listen_addr)?;

    // Skip connections where original dest equals listen addr (self-connection)
    if orig_dst == listen_addr {
        return Err("original destination is the listen address (loop detected)".into());
    }

    // Build initial metadata with IP-literal host for sniffer / DNS-snoop.
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: name.into(),
        in_port: listen_addr.port(),
        ..Default::default()
    };

    // Recover hostname:
    // 1. SnifferRuntime (TLS SNI or HTTP Host) — replaces the old enable_sni path
    // 2. Fall back to DNS snooping reverse lookup (IP → domain from recent DNS queries)
    if let Some(rt) = sniffer.as_deref() {
        rt.sniff(&stream, &mut metadata).await;
    }

    let mut hostname = metadata.sniff_host.clone();
    if hostname.is_empty() {
        if let Some(domain) = tunnel.resolver().reverse_lookup(orig_dst.ip()) {
            hostname = domain;
        }
    }

    // Prefer sniff_host for display but fall back to DNS-snooped hostname.
    metadata.host = hostname;

    debug!(
        "TProxy {} -> {} (host: {})",
        src_addr,
        orig_dst,
        if metadata.host.is_empty() {
            "<none>"
        } else {
            &metadata.host
        }
    );

    let inner = tunnel.inner();
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy(&metadata) else {
        return Err("no matching rule".into());
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let _guard = ConnectionGuard::track(
        &inner.stats,
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    );

    // Relay buffers on the future's stack — zero per-relay heap allocation (ADR-0011 T6).
    let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
    let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];

    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            let up = Arc::clone(_guard.counters());
            let dn = Arc::clone(_guard.counters());
            match copy_bidirectional_buf_tracked(
                &mut stream,
                &mut remote,
                &mut relay_buf_up,
                &mut relay_buf_dn,
                |n| {
                    inner
                        .stats
                        .record_upload(&up, n as meow_common::atomic::Int);
                },
                |n| {
                    inner
                        .stats
                        .record_download(&dn, n as meow_common::atomic::Int);
                },
            )
            .await
            {
                Ok((up, down)) => {
                    debug!("TProxy relay closed: up={up} down={down}");
                }
                Err(e) => debug!("TProxy relay error: {e}"),
            }
        }
        Err(e) => warn!("TProxy dial error: {e}"),
    }
    // _guard drops here, removing the entry from Statistics.
    Ok(())
}
