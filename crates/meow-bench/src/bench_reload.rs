/// Config-reload workload (#558): `PUT /configs` in a loop while a steady
/// connection-rate load runs through the proxy, with a datapath-rate
/// probe before and after, plus a committed-config verification.
/// Exercises the rebuild/publish chain end-to-end — YAML parse, semantic
/// proxy/rule rebuild, `reload_routing` route swap + tracked-conn kill —
/// under the mutation lane, against a live mixed listener.  (The A/B
/// configs differ only in the probe rule, so DNS and health-check
/// reconcile are no-ops here — those paths are covered by the config-
/// mutation tests, not this workload.)
///
/// PUTs alternate between two config files that differ in exactly one
/// probeable rule: `config_path` routes `DST-PORT <probe>` to a working
/// outbound, `alt_config_path` routes it to REJECT.  The proxy starts on
/// `config_path` and the first PUT is the REJECT variant, so every PUT is
/// a real config change (a "skip rebuild when unchanged" optimization
/// cannot void the measurement) and every committed generation is
/// observable through the datapath: each successful PUT is followed by a
/// datapath probe, and after the window a B commit must refuse the probe
/// and an A commit must echo.  Anything else means a reload was accepted
/// but never applied.
///
/// Note: `PUT /configs` is a *cold* reload — `reload_routing` closes
/// every tracked connection by design.  `load_conns_failed` therefore
/// has a systematic floor of roughly `reloads × concurrency` (each
/// commit drops the in-flight set); the pre/post probe rates and the
/// verification PUTs, not that counter, are the parity signal.
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5_client::socks5_connect;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReloadResult {
    /// PUT /configs requests issued during the measured window.
    pub reloads_attempted: usize,
    /// Reloads that returned 2xx.
    pub reloads_ok: usize,
    /// Wall-clock latency per reload, milliseconds.
    pub mean_reload_ms: f64,
    pub p95_reload_ms: f64,
    /// Echo connections completed while reloads were running.
    pub load_conns_ok: u64,
    /// Echo connections that failed during the reload window — includes
    /// the intentional cold-reload kills each commit performs.
    pub load_conns_failed: u64,
    /// Conns/sec over a short probe BEFORE the first reload — the
    /// baseline the post-reload probe is compared against.
    pub pre_reload_conns_per_sec: f64,
    /// Conns/sec over a short probe AFTER the last reload — parity means
    /// this stays within a factor of the pre-reload rate.
    pub post_reload_conns_per_sec: f64,
    /// Echo failures in the post-reload probe.
    pub post_reload_errors: u64,
    /// Datapath probes that observed the wrong committed config after a
    /// PUT (0–reloads+2): a 204 whose routing never reached the listener
    /// shows up here even when every probe conn succeeds.
    pub datapath_verify_failures: u64,
}

/// Minimal HTTP/1.0-ish PUT — meow-bench deliberately has no HTTP client
/// dependency; a fixed-shape JSON body over loopback needs none.
/// Returns the status code.  The whole exchange is bounded: a wedged
/// handler (e.g. a stuck mutation lane) must surface as a failed reload,
/// not hang the suite.
async fn http_put_json(api: SocketAddr, path: &str, body: &[u8]) -> anyhow::Result<u16> {
    tokio::time::timeout(
        Duration::from_secs(15),
        http_put_json_inner(api, path, body),
    )
    .await
    .map_err(|_| anyhow::anyhow!("PUT {path} timed out"))?
}

async fn http_put_json_inner(api: SocketAddr, path: &str, body: &[u8]) -> anyhow::Result<u16> {
    let mut s = tokio::net::TcpStream::connect(api).await?;
    let req = format!(
        "PUT {path} HTTP/1.1\r\nHost: {api}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).await?;
    s.write_all(body).await?;
    let mut resp = Vec::with_capacity(256);
    // Read until close (Connection: close) or the status line is in.
    let mut buf = [0u8; 1024];
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break; // headers complete — the status line is all we need
        }
        if resp.len() > 8192 {
            anyhow::bail!("oversized PUT /configs response head");
        }
    }
    let head = String::from_utf8_lossy(&resp);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed status line: {head:?}"))?;
    Ok(status)
}

/// How long each load connection echoes before the worker reconnects.
/// The load is background pressure for the reload window, not a churn
/// test: holding a conn ~200 ms keeps the turnover rate (~320 conn/s at
/// default concurrency — connect + 200 ms echo per worker) far below
/// loopback's ~16k ephemeral-port budget while still exercising the
/// accept path across every reload commit.
const CONN_LIFETIME: Duration = Duration::from_millis(200);

/// Background echo load: socks5 → echo round-trips for `CONN_LIFETIME`,
/// then reconnect, counted ok/failed per conn.  Runs until `until`
/// passes OR `stop` is set — the reload window uses the flag so the load
/// outlives the last PUT however long the PUT loop takes; the timed
/// probes pass a flag that is never set and rely on `until` alone.
/// A conn that connects but echoes zero bytes before the window closed
/// is counted on neither counter — it neither proves nor disproves the
/// datapath.
fn spawn_load(
    proxy: SocketAddr,
    echo: SocketAddr,
    concurrency: usize,
    until: Instant,
    stop: &Arc<AtomicBool>,
) -> (
    Vec<tokio::task::JoinHandle<()>>,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
) {
    let ok = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let (ok, failed, stop) = (Arc::clone(&ok), Arc::clone(&failed), Arc::clone(stop));
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) && Instant::now() < until {
                // Bound the connect by the window end: an in-flight
                // socks5 handshake can otherwise stretch the measured
                // window ~10 s past `until`, skewing the probe-rate
                // denominator with a stall tail.
                let remaining = until.saturating_duration_since(Instant::now());
                let connect = tokio::time::timeout(remaining, socks5_connect(proxy, echo)).await;
                match connect {
                    Err(_) => break, // window ended mid-connect — neutral, like Ok(Ok(0)) below
                    Ok(Err(_)) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        // Backoff on failure: without it a dead listener
                        // spins workers into ephemeral-port exhaustion.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Ok(Ok(mut stream)) => {
                        // Echo until the conn ages out or drops.  A PUT
                        // commit kills every live conn by design (cold
                        // reload), so mid-conn drops land in `failed`.
                        let conn_end = (Instant::now() + CONN_LIFETIME).min(until);
                        let echoed = tokio::time::timeout(Duration::from_secs(10), async {
                            let mut rounds = 0u64;
                            while Instant::now() < conn_end {
                                stream.write_all(&[0x42]).await?;
                                let mut b = [0u8; 1];
                                stream.read_exact(&mut b).await?;
                                rounds += 1;
                            }
                            Ok::<_, std::io::Error>(rounds)
                        })
                        .await;
                        match echoed {
                            // Connected as the window closed — counted on neither side.
                            Ok(Ok(0)) => {}
                            Ok(Ok(_)) => {
                                ok.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        };
                    }
                }
            }
        }));
    }
    (handles, ok, failed)
}

/// Run the same 3 s load the parity probes use; returns conns/sec and
/// the failure count.
async fn probe_rate(proxy: SocketAddr, echo: SocketAddr, concurrency: usize) -> (f64, u64) {
    let never = Arc::new(AtomicBool::new(false));
    let probe_start = Instant::now();
    let (ph, pok, pfail) = spawn_load(
        proxy,
        echo,
        concurrency,
        probe_start + Duration::from_secs(3),
        &never,
    );
    for h in ph {
        let _ = h.await;
    }
    let elapsed = probe_start.elapsed().as_secs_f64();
    (
        pok.load(Ordering::Relaxed) as f64 / elapsed,
        pfail.load(Ordering::Relaxed),
    )
}

/// One datapath probe through the proxy to `probe_addr`.  `expect_echo`
/// is `true` when the probe rule should route to a working outbound
/// (config A), `false` when it should be REJECTed (config B).  The whole
/// probe is bounded: a committed config that leaves the datapath
/// half-wedged (SOCKS5 handshake completes, echo never returns) must
/// surface as a verification failure, not hang the suite.
async fn datapath_probe(proxy: SocketAddr, probe_addr: SocketAddr, expect_echo: bool) -> bool {
    let ok = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = socks5_connect(proxy, probe_addr).await?;
        stream.write_all(&[0x42]).await?;
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        Ok::<_, std::io::Error>(b[0] == 0x42)
    })
    .await
    .unwrap_or(Ok(false))
    .unwrap_or(false);
    ok == expect_echo
}

/// The endpoints the reload workload needs — grouped so `bench_reload`
/// stays readable (mixed listener, echo target, probe listener, API).
pub struct ReloadTarget {
    /// Mixed-port the load traffic and probes go through.
    pub proxy: SocketAddr,
    /// Echo server the background load round-trips.
    pub echo: SocketAddr,
    /// Fixed-port echo listener the two configs route differently
    /// (`DST-PORT <probe>` → outbound vs REJECT).
    pub probe_addr: SocketAddr,
    /// external-controller address for `PUT /configs`.
    pub api: SocketAddr,
}

/// Run `reloads` PUTs spread across `duration_secs`, alternating between
/// `config_path` and `alt_config_path`, while `concurrency` echo loops
/// run; then probe the datapath rate and verify the committed config is
/// observable.
pub async fn bench_reload(
    target: ReloadTarget,
    config_path: &Path,
    alt_config_path: &Path,
    duration_secs: u64,
    concurrency: usize,
    reloads: usize,
) -> anyhow::Result<ReloadResult> {
    let ReloadTarget {
        proxy,
        echo,
        probe_addr,
        api,
    } = target;
    anyhow::ensure!(
        reloads > 0 && concurrency > 0,
        "--reloads and --concurrency must both be > 0"
    );
    let body_for = |path: &Path| {
        let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        serde_json::json!({"path": abs.to_string_lossy()}).to_string()
    };
    let body_a = body_for(config_path);
    let body_b = body_for(alt_config_path);

    // Baseline rate BEFORE the reloads — "parity" afterwards is measured
    // against this, not just "nonzero".
    eprintln!("  reload: pre-reload probe (3 s)...");
    let (pre_rate, pre_err) = probe_rate(proxy, echo, concurrency).await;
    anyhow::ensure!(
        pre_rate > 0.0,
        "datapath not delivering before the first reload \
         ({pre_err} errors, 0 successful conns in pre-probe)"
    );

    // PUTs land at ~spacing intervals.  The load window is driven by the
    // `stop` flag, not a precomputed deadline: PUT latencies accumulate,
    // so the window ends when the LAST PUT completes (with a generous
    // hard cap as a hang backstop).
    let reloads_u32 = u32::try_from(reloads).unwrap_or(u32::MAX).max(1);
    let spacing = Duration::from_secs(duration_secs) / reloads_u32;
    let hard_cap = Instant::now()
        + Duration::from_secs(duration_secs)
        + spacing * reloads_u32.min(4)
        + Duration::from_secs(120);
    let stop = Arc::new(AtomicBool::new(false));
    let (handles, ok, failed) = spawn_load(proxy, echo, concurrency, hard_cap, &stop);

    let mut latencies = Vec::with_capacity(reloads);
    let mut reloads_ok = 0usize;
    let mut datapath_verify_failures = 0u64;
    // The proxy starts on config A, so the first PUT is the B (REJECT)
    // variant — every measured PUT is a real config transition, and the
    // final PUT leaves A committed, so both verification PUTs below are
    // real transitions too.
    for i in 0..reloads {
        tokio::time::sleep(spacing).await;
        let t = Instant::now();
        let (body, expect_echo) = if i % 2 == 0 {
            (&body_b, false)
        } else {
            (&body_a, true)
        };
        match http_put_json(api, "/configs", body.as_bytes()).await {
            Ok(status) if (200..300).contains(&status) => {
                reloads_ok += 1;
                latencies.push(t.elapsed().as_secs_f64() * 1000.0);
                // `PUT /configs` commits synchronously before responding,
                // so the probe observes the just-committed generation — a
                // 204 whose routing never landed fails here instead of
                // being masked by the next commit.
                if !datapath_probe(proxy, probe_addr, expect_echo).await {
                    datapath_verify_failures += 1;
                    eprintln!(
                        "  reload: VERIFY FAILED — PUT {i} committed {} but the datapath disagrees",
                        if expect_echo { "A" } else { "B" }
                    );
                }
            }
            Ok(status) => eprintln!("  reload: PUT /configs → HTTP {status}"),
            Err(e) => eprintln!("  reload: PUT /configs failed: {e}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = latencies.len();
    let mean = if n > 0 {
        latencies.iter().sum::<f64>() / n as f64
    } else {
        0.0
    };
    let p95 = if n > 0 {
        latencies[((n as f64 * 0.95) as usize).min(n - 1)]
    } else {
        0.0
    };

    // End-state verification: commit B (probe rule → REJECT) then A
    // (probe rule → outbound), checking the listener observes each.  With
    // the default even `--reloads` the loop above ends on A, so both of
    // these are real transitions too; either way a commit that never
    // reaches the datapath shows up here even if the echo probes passed
    // on a stale table.
    for (body, expect_echo, label) in [
        (&body_b, false, "B (probe → REJECT)"),
        (&body_a, true, "A (probe → outbound)"),
    ] {
        match http_put_json(api, "/configs", body.as_bytes()).await {
            Ok(status) if (200..300).contains(&status) => {
                if !datapath_probe(proxy, probe_addr, expect_echo).await {
                    datapath_verify_failures += 1;
                    eprintln!(
                        "  reload: VERIFY FAILED — committed {label} but the datapath disagrees"
                    );
                }
            }
            other => {
                datapath_verify_failures += 1;
                eprintln!("  reload: verification PUT {label} failed: {other:?}");
            }
        }
    }

    // Post-reload probe: 3 s of the same load, measured against the
    // ACTUAL elapsed time — in-flight connects can run past the nominal
    // window, and a fixed denominator would overstate the rate precisely
    // when the proxy is degraded.
    eprintln!("  reload: post-reload probe (3 s)...");
    let (post_rate, post_err) = probe_rate(proxy, echo, concurrency).await;

    eprintln!(
        "  reload: {reloads_ok}/{reloads} ok  mean {mean:.1} ms  p95 {p95:.1} ms  \
         pre {pre_rate:.0} → post {post_rate:.0} conns/s ({post_err} errors)  \
         verify failures {datapath_verify_failures}"
    );

    Ok(ReloadResult {
        reloads_attempted: reloads,
        reloads_ok,
        mean_reload_ms: mean,
        p95_reload_ms: p95,
        load_conns_ok: ok.load(Ordering::Relaxed),
        load_conns_failed: failed.load(Ordering::Relaxed),
        pre_reload_conns_per_sec: pre_rate,
        post_reload_conns_per_sec: post_rate,
        post_reload_errors: post_err,
        datapath_verify_failures,
    })
}
