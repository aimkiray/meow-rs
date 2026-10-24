use crate::internal_http;
use crate::raw::{RawGeoDataConfig, RawGeoXUrl};
use anyhow::anyhow;
use meow_common::adapter::Proxy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

const DEFAULT_MMDB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb";
const DEFAULT_ASN_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb";
const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat";

/// Validated `geodata:` config, produced by [`parse_geodata`].
#[derive(Debug, Clone)]
pub struct GeoDataConfig {
    pub mmdb_path: Option<PathBuf>,
    pub asn_path: Option<PathBuf>,
    pub geosite_path: Option<PathBuf>,
    pub auto_update: bool,
    /// Hours between update checks (≥1).
    pub auto_update_interval: u32,
    pub mmdb_url: String,
    pub asn_url: String,
    pub geosite_url: String,
    /// `geodata.proxy` verbatim — resolved against the built proxy map by
    /// `resolve_geodata_download_proxy` at download time (`DIRECT` and the
    /// other built-in terminal names mean "fetch direct").
    pub proxy: Option<String>,
}

impl Default for GeoDataConfig {
    fn default() -> Self {
        Self {
            mmdb_path: None,
            asn_path: None,
            geosite_path: None,
            auto_update: false,
            auto_update_interval: 24,
            mmdb_url: DEFAULT_MMDB_URL.to_string(),
            asn_url: DEFAULT_ASN_URL.to_string(),
            geosite_url: DEFAULT_GEOSITE_URL.to_string(),
            proxy: None,
        }
    }
}

/// Parse and validate the raw `geodata:` block plus the top-level
/// `geox-url:` alias. Returns `GeoDataConfig::default()` when both are
/// absent — `geox-url` on its own (no `geodata:` block) is enough to
/// override the download URLs.
///
/// URL precedence is per key: `geodata.url.*` > `geox-url.*` > baked-in
/// default. `geox-url.geoip` is accepted and ignored with a warning —
/// mihomo points it at `geoip.dat` and meow-rs has no geoip.dat consumer.
pub fn parse_geodata(
    raw: Option<&RawGeoDataConfig>,
    geox: Option<&RawGeoXUrl>,
) -> Result<GeoDataConfig, anyhow::Error> {
    if geox.and_then(|g| g.geoip.as_ref()).is_some() {
        warn!(
            "geox-url.geoip: meow-rs has no geoip.dat consumer — the key is \
             ignored. To override the GeoIP MMDB download URL use \
             `geox-url.mmdb` or `geodata.url.mmdb`"
        );
    }

    // `geodata.url.*` wins; `geox-url.*` fills in what it leaves unset;
    // the baked-in default is last. Each key merges independently.
    let pick = |explicit: Option<&String>, alias: Option<&String>, default: &str| {
        explicit
            .or(alias)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };

    let Some(r) = raw else {
        return Ok(GeoDataConfig {
            mmdb_url: pick(None, geox.and_then(|g| g.mmdb.as_ref()), DEFAULT_MMDB_URL),
            asn_url: pick(None, geox.and_then(|g| g.asn.as_ref()), DEFAULT_ASN_URL),
            geosite_url: pick(
                None,
                geox.and_then(|g| g.geosite.as_ref()),
                DEFAULT_GEOSITE_URL,
            ),
            ..GeoDataConfig::default()
        });
    };

    // Warn on upstream-only fields (Class B per ADR-0002 §geodata-subsection.md).
    for (name, val) in [
        ("geodata-mode", &r.geodata_mode),
        ("geodata-loader", &r.geodata_loader),
        ("geoip-matcher", &r.geoip_matcher),
    ] {
        if val.is_some() {
            warn!(
                "geodata.{}: field is not supported in meow-rs and will be ignored \
                (upstream: config.go); remove it to suppress this warning",
                name
            );
        }
    }

    let interval = r.auto_update_interval.unwrap_or(24);
    if interval == 0 {
        return Err(anyhow!(
            "geodata.auto-update-interval must be at least 1 hour (got 0)"
        ));
    }
    // Same ceiling as the rule-provider refresh supervisor
    // (`MAX_REFRESH_INTERVAL_SECS`, ~10 years): `Instant + Duration`
    // overflows — and `tokio::time::interval` panics — on absurd values.
    const MAX_AUTO_UPDATE_INTERVAL_HOURS: u32 = 10 * 365 * 24;
    let interval = interval.min(MAX_AUTO_UPDATE_INTERVAL_HOURS);
    if interval != r.auto_update_interval.unwrap_or(24) {
        warn!(
            "geodata.auto-update-interval {}h exceeds the {}h ceiling; clamped",
            r.auto_update_interval.unwrap_or(24),
            MAX_AUTO_UPDATE_INTERVAL_HOURS
        );
    }

    let urls = r.url.as_ref();
    Ok(GeoDataConfig {
        mmdb_path: r.mmdb_path.as_deref().map(PathBuf::from),
        asn_path: r.asn_path.as_deref().map(PathBuf::from),
        geosite_path: r.geosite_path.as_deref().map(PathBuf::from),
        auto_update: r.auto_update,
        auto_update_interval: interval,
        mmdb_url: pick(
            urls.and_then(|u| u.mmdb.as_ref()),
            geox.and_then(|g| g.mmdb.as_ref()),
            DEFAULT_MMDB_URL,
        ),
        asn_url: pick(
            urls.and_then(|u| u.asn.as_ref()),
            geox.and_then(|g| g.asn.as_ref()),
            DEFAULT_ASN_URL,
        ),
        geosite_url: pick(
            urls.and_then(|u| u.geosite.as_ref()),
            geox.and_then(|g| g.geosite.as_ref()),
            DEFAULT_GEOSITE_URL,
        ),
        proxy: r.proxy.clone(),
    })
}

/// Download `url` and atomically replace `dest` via a `.tmp` sibling.
///
/// When `proxy` is `Some`, the HTTP fetch is tunneled through that proxy
/// adapter (used so GFW-blocked CDNs stay reachable on background refresh);
/// otherwise the OS handles connectivity directly.
///
/// Returns `Ok(())` on success. On failure the temp file is removed (best-
/// effort) and the original `dest` is untouched.
pub async fn download_and_replace(
    url: &str,
    dest: &Path,
    proxy: Option<&Arc<dyn Proxy>>,
) -> Result<(), anyhow::Error> {
    // Unique scratch, not `with_extension("tmp")` — same-stem targets
    // (`Country.mmdb`/`Country.yaml` → `Country.tmp`) and concurrent
    // downloaders (auto-update vs rebuild-time `ensure_geodata`) must not
    // share it (issue #543 review). Sweep scratch a crashed downloader
    // orphaned (issue #621) — on the blocking pool, off the async worker.
    {
        let sweep_target = dest.to_path_buf();
        let _ = crate::spawn_blocking_with_current_dispatcher(move || {
            meow_common::fs_util::sweep_scratch_siblings(
                &sweep_target,
                meow_common::fs_util::SCRATCH_STALE_AGE,
            );
            // The pre-#543 scratch was `with_extension("tmp")`
            // (`Country.mmdb` → `Country.tmp`) — it does not match the
            // `{base}.{pid}.{n}.tmp` sweep shape; remove it only when old
            // (a young file could be a user's own).
            let legacy = sweep_target.with_extension("tmp");
            if legacy != sweep_target {
                let old = std::fs::metadata(&legacy)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| {
                        SystemTime::now().duration_since(t).unwrap_or_default()
                            > meow_common::fs_util::SCRATCH_STALE_AGE
                    });
                if old {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
        })
        .await;
    }
    let tmp = crate::unique_scratch_path(dest);

    if let Some(p) = proxy {
        info!(
            "auto-update: downloading {} from {} via proxy '{}'",
            dest.display(),
            url,
            p.name()
        );
    } else {
        info!("auto-update: downloading {} from {}", dest.display(), url);
    }

    // Geodata-only opt-in: a failed proxy dial retries direct — see
    // `internal_http::fetch_or_direct` for the connect-phase-only contract.
    let bytes = internal_http::fetch_or_direct(url, proxy, &[])
        .await
        .map_err(|e| anyhow!("fetching {url}: {e}"))?;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&tmp, &bytes).await?;

    if let Err(e) = tokio::fs::rename(&tmp, dest).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "atomic rename {} → {}: {}",
            tmp.display(),
            dest.display(),
            e
        ));
    }

    info!(
        "auto-update: {} updated ({} bytes)",
        dest.display(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls};

    fn raw_defaults() -> RawGeoDataConfig {
        RawGeoDataConfig::default()
    }

    fn parse(raw: Option<&RawGeoDataConfig>) -> Result<GeoDataConfig, anyhow::Error> {
        parse_geodata(raw, None)
    }

    #[test]
    fn absent_block_returns_defaults() {
        let cfg = parse(None).unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 24);
        assert!(cfg.mmdb_path.is_none());
        assert!(cfg.asn_path.is_none());
        assert!(cfg.geosite_path.is_none());
        assert!(cfg.mmdb_url.contains("country.mmdb"));
        assert!(cfg.asn_url.contains("GeoLite2-ASN"));
        assert!(cfg.geosite_url.contains("geosite.dat"));
        assert!(cfg.proxy.is_none());
    }

    #[test]
    fn explicit_paths_override_discovery() {
        let raw = RawGeoDataConfig {
            mmdb_path: Some("/custom/Country.mmdb".to_string()),
            asn_path: Some("/custom/ASN.mmdb".to_string()),
            geosite_path: Some("/custom/geosite.mrs".to_string()),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(
            cfg.mmdb_path.unwrap().to_str().unwrap(),
            "/custom/Country.mmdb"
        );
        assert_eq!(cfg.asn_path.unwrap().to_str().unwrap(), "/custom/ASN.mmdb");
        assert_eq!(
            cfg.geosite_path.unwrap().to_str().unwrap(),
            "/custom/geosite.mrs"
        );
    }

    #[test]
    fn url_overrides_replace_defaults() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                mmdb: Some("https://example.com/country.mmdb".to_string()),
                asn: None,
                geosite: Some("https://example.com/geosite.mrs".to_string()),
            }),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://example.com/country.mmdb");
        assert!(cfg.asn_url.contains("GeoLite2-ASN")); // default preserved
        assert_eq!(cfg.geosite_url, "https://example.com/geosite.mrs");
    }

    #[test]
    fn proxy_passthrough() {
        let raw = RawGeoDataConfig {
            proxy: Some("HK 01".to_string()),
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.proxy.as_deref(), Some("HK 01"));
    }

    #[test]
    fn interval_zero_is_hard_error() {
        let raw = RawGeoDataConfig {
            auto_update_interval: Some(0),
            ..raw_defaults()
        };
        let err = parse(Some(&raw)).unwrap_err();
        assert!(
            err.to_string().contains("at least 1 hour"),
            "error should mention minimum interval: {err}"
        );
    }

    #[test]
    fn absent_interval_defaults_to_24() {
        let raw = RawGeoDataConfig {
            auto_update: true,
            auto_update_interval: None,
            ..raw_defaults()
        };
        let cfg = parse(Some(&raw)).unwrap();
        assert_eq!(cfg.auto_update_interval, 24);
    }

    #[test]
    fn upstream_only_fields_do_not_error() {
        // geodata-mode, geodata-loader, geoip-matcher accepted without error.
        let raw = RawGeoDataConfig {
            geodata_mode: Some(serde_json::Value::String("memconservative".to_string())),
            geodata_loader: Some(serde_json::Value::String("standard".to_string())),
            geoip_matcher: Some(serde_json::Value::String("succinct".to_string())),
            ..raw_defaults()
        };
        // Must not error — warn-only (Class B per ADR-0002).
        parse(Some(&raw)).unwrap();
    }

    // ── geox-url alias ────────────────────────────────────────────

    /// `geox-url` alone (no `geodata:` block) must still take effect —
    /// the early return for a missing `geodata:` section must not skip it.
    #[test]
    fn geox_url_alone_overrides_defaults() {
        let geox = RawGeoXUrl {
            mmdb: Some("https://cdn.test/Country.mmdb".to_string()),
            asn: Some("https://cdn.test/ASN.mmdb".to_string()),
            geosite: None,
            geoip: None,
        };
        let cfg = parse_geodata(None, Some(&geox)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://cdn.test/Country.mmdb");
        assert_eq!(cfg.asn_url, "https://cdn.test/ASN.mmdb");
        assert!(
            cfg.geosite_url.contains("geosite.dat"),
            "unset keys keep the baked-in default"
        );
    }

    /// `geodata.url.*` beats `geox-url.*` per key — keys the explicit
    /// block leaves unset still fall through to the alias.
    #[test]
    fn geodata_url_wins_over_geox_per_key() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                mmdb: Some("https://explicit.test/Country.mmdb".to_string()),
                asn: None,
                geosite: None,
            }),
            ..raw_defaults()
        };
        let geox = RawGeoXUrl {
            mmdb: Some("https://alias.test/Country.mmdb".to_string()),
            asn: Some("https://alias.test/ASN.mmdb".to_string()),
            geosite: Some("https://alias.test/geosite.dat".to_string()),
            geoip: None,
        };
        let cfg = parse_geodata(Some(&raw), Some(&geox)).unwrap();
        assert_eq!(
            cfg.mmdb_url, "https://explicit.test/Country.mmdb",
            "geodata.url.mmdb beats geox-url.mmdb"
        );
        assert_eq!(
            cfg.asn_url, "https://alias.test/ASN.mmdb",
            "asn falls through to the alias"
        );
        assert_eq!(
            cfg.geosite_url, "https://alias.test/geosite.dat",
            "geosite falls through to the alias"
        );
    }

    /// `geox-url.geoip` must be ignored, not folded into `mmdb` — upstream
    /// points it at `geoip.dat`, which has no consumer here.
    #[test]
    fn geox_url_geoip_is_ignored() {
        let geox = RawGeoXUrl {
            geoip: Some("https://alias.test/geoip.dat".to_string()),
            ..RawGeoXUrl::default()
        };
        let cfg = parse_geodata(None, Some(&geox)).unwrap();
        assert!(
            cfg.mmdb_url.contains("country.mmdb"),
            "geoip must not leak into the mmdb URL: {}",
            cfg.mmdb_url
        );
    }

    /// An empty `geox-url:` map changes nothing.
    #[test]
    fn empty_geox_url_is_a_noop() {
        let cfg = parse_geodata(None, Some(&RawGeoXUrl::default())).unwrap();
        assert_eq!(cfg.mmdb_url, DEFAULT_MMDB_URL);
        assert_eq!(cfg.asn_url, DEFAULT_ASN_URL);
        assert_eq!(cfg.geosite_url, DEFAULT_GEOSITE_URL);
    }

    // ── download_and_replace (geodata-only direct fallback) ────────────

    /// A `Proxy` whose `dial_tcp` always fails — models an unreachable
    /// upstream so the connect phase itself errors.
    struct FailingDialProxy {
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for FailingDialProxy {
        fn name(&self) -> &str {
            "failing"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported(
                "failing: connect refused".into(),
            ))
        }
        async fn dial_udp(
            &self,
            _m: &meow_common::Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "failing: dial_udp".into(),
            ))
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl Proxy for FailingDialProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            Vec::new()
        }
    }

    /// Serve `response` to every accepted connection — the geodata direct
    /// fallback dials a second time after the proxy dial fails, so the
    /// origin must accept more than once.
    async fn spawn_test_origin(response: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(response).await;
                });
            }
        });
        format!("http://{addr}/Country.mmdb")
    }

    /// Integration pin for the geodata-only opt-in: a configured download
    /// proxy whose connect phase fails must NOT sink the download — the
    /// fetch retries direct (`internal_http::fetch_or_direct`) and the
    /// file lands on disk.
    #[tokio::test]
    async fn download_and_replace_falls_back_to_direct_after_dial_failure() {
        let url = spawn_test_origin(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").await;
        let proxy: Arc<dyn Proxy> = Arc::new(FailingDialProxy {
            health: meow_common::ProxyHealth::new(),
        });
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Country.mmdb");
        download_and_replace(&url, &dest, Some(&proxy))
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
    }

    /// A working direct fetch still lands without any proxy configured.
    #[tokio::test]
    async fn download_and_replace_direct_writes_file() {
        let url = spawn_test_origin(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxy").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("geosite.dat");
        download_and_replace(&url, &dest, None).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"xy");
    }
}
