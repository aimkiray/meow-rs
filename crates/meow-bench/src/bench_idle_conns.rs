/// Benchmark: 10 000 concurrent idle SOCKS5 sessions.
///
/// Establishes N simultaneous SOCKS5 connections through the proxy, then
/// holds them open for `hold_secs` without sending any data.  Samples RSS
/// at 1 Hz over the hold window to capture the per-connection bookkeeping
/// cost isolated from relay-buffer cost.
///
/// This is ADR-0011 measurement M-idle from the footprint baseline spec.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::bench_memory::measure_rss;
use crate::socks5_client::socks5_connect;

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdleConnsResult {
    /// Idle connections requested — consumers gate on `live_connections`
    /// vs this before trusting `bytes_per_idle_conn` (ephemeral-port
    /// budget can collapse establishment on constrained hosts).
    pub requested_connections: usize,
    /// Number of idle connections successfully established.
    pub live_connections: usize,
    /// Peak RSS (bytes) observed while holding idle connections.
    pub peak_rss_bytes: u64,
    /// Estimated bytes of RSS per idle connection.
    pub bytes_per_idle_conn: f64,
}

pub async fn bench_idle_conns(
    proxy: SocketAddr,
    echo: SocketAddr,
    n_conns: usize,
    hold_secs: u64,
    proxy_pid: u32,
) -> anyhow::Result<IdleConnsResult> {
    eprintln!("  idle-conns: establishing {n_conns} connections...");

    // Warm the datapath so first-conn lazy init (resolver/rule caches,
    // adapter warm paths) is excluded from the per-conn delta below.
    for _ in 0..8 {
        if let Ok(mut s) = socks5_connect(proxy, echo).await {
            use tokio::io::AsyncReadExt;
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                s.write_all(&[0x42]).await?;
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await?;
                Ok::<_, std::io::Error>(())
            })
            .await;
        }
    }

    // Record idle RSS before opening connections.
    let rss_before = measure_rss(proxy_pid)?;

    // Open connections with bounded in-flight concurrency and a paced
    // issue rate: firing all N connects at once overflows the listener's
    // accept backlog and most attempts are refused before the handshake
    // even runs.  ~1 ms spacing keeps the issue rate ≈1000 conn/s.
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    let mut handles = Vec::with_capacity(n_conns);
    for _ in 0..n_conns {
        let permits = Arc::clone(&permits);
        handles.push(tokio::spawn(async move {
            let _permit = permits.acquire().await.ok()?;
            socks5_connect(proxy, echo).await.ok()
        }));
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Collect live streams; count successes.
    let mut streams = Vec::with_capacity(n_conns);
    for h in handles {
        if let Ok(Some(s)) = h.await {
            streams.push(s);
        }
    }
    let live = streams.len();
    eprintln!("  idle-conns: {live}/{n_conns} connections live — holding {hold_secs}s");
    if live < n_conns / 2 {
        eprintln!(
            "  idle-conns: WARN only {live}/{n_conns} established — \
             ephemeral-port budget or fd cap collapsed the sample"
        );
    }

    // Sample peak RSS over the hold window.
    let mut peak_rss = rss_before;
    let mut sampled = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(hold_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(rss) = measure_rss(proxy_pid) {
            peak_rss = peak_rss.max(rss);
            sampled = true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    // Total sampling failure silently yields delta=0 — a fake "0 bytes per
    // conn" trend point is worse than a failed leg.
    anyhow::ensure!(
        sampled,
        "idle-conns: no RSS samples collected during the hold window"
    );

    // Drain streams — shut them down cleanly so the proxy can free them.
    for mut s in streams {
        let _ = s.shutdown().await;
    }

    let rss_delta = peak_rss.saturating_sub(rss_before);
    let bytes_per_conn = if live > 0 {
        rss_delta as f64 / live as f64
    } else {
        0.0
    };

    eprintln!(
        "  idle-conns: RSS before={:.1} MB  peak={:.1} MB  delta={:.1} MB  {:.0} bytes/conn",
        rss_before as f64 / 1_048_576.0,
        peak_rss as f64 / 1_048_576.0,
        rss_delta as f64 / 1_048_576.0,
        bytes_per_conn,
    );

    Ok(IdleConnsResult {
        requested_connections: n_conns,
        live_connections: live,
        peak_rss_bytes: peak_rss,
        bytes_per_idle_conn: bytes_per_conn,
    })
}
