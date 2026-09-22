use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bench_memory::measure_rss;
use crate::socks5_client::socks5_connect;

/// Per-connection echo deadline: a proxy whose echo never returns must not
/// wedge a worker forever — time it out and move on to the next conn.
const ECHO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnRateResult {
    pub duration_secs: f64,
    pub total_connections: u64,
    pub connections_per_sec: f64,
    /// Connections whose echo phase hit the deadline (a proxy that
    /// accepted the CONNECT but never answered).
    pub echo_timeouts: u64,
}

pub async fn bench_conn_rate(
    proxy: SocketAddr,
    echo: SocketAddr,
    duration_secs: u64,
    concurrency: usize,
) -> anyhow::Result<ConnRateResult> {
    let counter = Arc::new(AtomicU64::new(0));
    let echo_timeouts = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let counter = Arc::clone(&counter);
        let echo_timeouts = Arc::clone(&echo_timeouts);
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let Ok(mut stream) = socks5_connect(proxy, echo).await else {
                    // Backoff on failure — a dead listener would otherwise
                    // spin every worker hot for the rest of the window
                    // (same pattern as bench_reload's spawn_load).
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                let timed_out = tokio::time::timeout(ECHO_TIMEOUT, async {
                    if stream.write_all(&[0x42]).await.is_ok() {
                        let mut buf = [0u8; 1];
                        let _ = stream.read_exact(&mut buf).await;
                    }
                })
                .await
                .is_err();
                drop(stream);
                if timed_out {
                    echo_timeouts.fetch_add(1, Ordering::Relaxed);
                }
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total = counter.load(Ordering::Relaxed);
    let timeouts = echo_timeouts.load(Ordering::Relaxed);
    // Measured elapsed, not the configured duration: workers may run past
    // the deadline by up to CONNECT_TIMEOUT + ECHO_TIMEOUT (~20 s) on
    // their last in-flight conn, so dividing by `duration_secs` would
    // understate the rate.
    let actual_elapsed = start.elapsed().as_secs_f64();
    let cps = total as f64 / actual_elapsed;

    eprintln!("  conn-rate: {total} connections in {actual_elapsed:.1}s = {cps:.0}/s");
    if timeouts > 0 {
        eprintln!("  echo-timeouts: {timeouts} connections never answered their echo");
    }

    Ok(ConnRateResult {
        duration_secs: actual_elapsed,
        total_connections: total,
        connections_per_sec: cps,
        echo_timeouts: timeouts,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SteadyStateResult {
    pub sample_count: usize,
    /// Median `(rss - idle_rss) / concurrency` — the per-connection heap
    /// delta the documented ~35 KB baseline and <32 KB M2 target use.
    pub median_bytes_per_conn: f64,
    pub p95_bytes_per_conn: f64,
    /// Median absolute RSS under load (context for the delta).
    pub median_rss_bytes: u64,
    /// RSS sampled before the workload started — the delta baseline.
    pub idle_rss_bytes: u64,
}

/// Steady-state bytes-per-connection measurement (ADR-0011 §2 M-steady).
///
/// Runs a `bench_conn_rate`-style workload for `duration_secs`, then samples
/// the proxy's RSS at 4 Hz over the **middle** `sample_secs` window.
/// Returns the median and p95 of `(rss - idle_rss) / live_conn_count` — the
/// *delta* over the idle baseline captured before workers spawn, matching
/// the ~35 KB/conn figure in `docs/benchmarks/footprint-rss-baseline.md`
/// and the <32 KB M2 target (absolute RSS/conn can never reach it: even a
/// zero-overhead conn carries the ~9 MB idle floor).
///
/// `live_conn_count` is approximated as `concurrency` (the number of
/// inflight concurrent requests) — the true live count converges to it at
/// steady state since each worker keeps one connection open at a time.
///
/// This is the headline M2 close-summary number per architect directive
/// 2026-05-12.
pub async fn bench_connrate_steady_state(
    proxy: SocketAddr,
    echo: SocketAddr,
    duration_secs: u64,
    concurrency: usize,
    proxy_pid: u32,
) -> anyhow::Result<SteadyStateResult> {
    anyhow::ensure!(
        duration_secs >= 3,
        "steady-state needs --duration >= 3 (middle-third sample window)"
    );
    // Warm the datapath before the baseline: first-conn lazy init
    // (resolver/rule caches, adapter warm paths) would otherwise land in
    // the per-conn delta.
    for _ in 0..8 {
        if let Ok(mut s) = socks5_connect(proxy, echo).await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = tokio::time::timeout(ECHO_TIMEOUT, async {
                s.write_all(&[0x42]).await?;
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await?;
                Ok::<_, std::io::Error>(())
            })
            .await;
        }
    }
    // Idle baseline: the proxy is already up but no load has run — the
    // delta against the loaded samples is the per-conn footprint.  A
    // failed `ps` must fail the leg: `unwrap_or(0)` would silently turn
    // the delta metric into absolute RSS/conn.
    let idle_rss = measure_rss(proxy_pid)?;
    let counter = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    // Spawn connrate workers (same pattern as bench_conn_rate).
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let Ok(mut stream) = socks5_connect(proxy, echo).await else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                let _ = tokio::time::timeout(ECHO_TIMEOUT, async {
                    if stream.write_all(&[0x42]).await.is_ok() {
                        let mut buf = [0u8; 1];
                        let _ = stream.read_exact(&mut buf).await;
                    }
                })
                .await;
                drop(stream);
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Compute the middle-third sampling window.
    let warmup = duration_secs / 3;
    let sample_end = 2 * duration_secs / 3;
    let start = Instant::now();

    // Skip warmup.
    while start.elapsed().as_secs() < warmup {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Sample at 4 Hz over the middle third — at the default
    // `--duration 10` the window is only ~3 s, and single-digit n makes
    // p95 pure noise.
    let mut samples: Vec<f64> = Vec::new();
    let mut rss_samples: Vec<u64> = Vec::new();
    while start.elapsed().as_secs() < sample_end {
        if let Ok(rss) = measure_rss(proxy_pid) {
            // At steady state, concurrency == number of inflight connections.
            // The metric is the DELTA over the idle baseline — absolute
            // RSS/conn counts the ~9 MB idle floor toward every conn.
            let bytes_per_conn = rss.saturating_sub(idle_rss) as f64 / concurrency as f64;
            samples.push(bytes_per_conn);
            rss_samples.push(rss);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Wait for workers.
    for h in handles {
        let _ = h.await;
    }

    // Zero samples means every `ps` call failed — serializing a zeroed
    // result would poison the trend with a plausible-looking garbage
    // point; fail the leg instead.
    anyhow::ensure!(
        !samples.is_empty(),
        "steady-state: no RSS samples collected (every measure_rss call failed)"
    );

    // Compute median + p95.
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    rss_samples.sort();

    let n = samples.len();
    let median_bytes_per_conn = if n > 0 { samples[n / 2] } else { 0.0 };
    let p95_bytes_per_conn = if n > 0 {
        samples[((n as f64 * 0.95) as usize).min(n - 1)]
    } else {
        0.0
    };
    let median_rss_bytes = if rss_samples.is_empty() {
        0
    } else {
        rss_samples[rss_samples.len() / 2]
    };

    eprintln!(
        "  steady-state: {n} samples  median {:.0} bytes/conn  p95 {:.0} bytes/conn  median RSS {:.1} MB (idle {:.1} MB)",
        median_bytes_per_conn,
        p95_bytes_per_conn,
        median_rss_bytes as f64 / 1_048_576.0,
        idle_rss as f64 / 1_048_576.0,
    );

    Ok(SteadyStateResult {
        sample_count: n,
        median_bytes_per_conn,
        p95_bytes_per_conn,
        median_rss_bytes,
        idle_rss_bytes: idle_rss,
    })
}
