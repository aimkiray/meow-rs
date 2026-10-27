//! Boundary tests pinning the serde-saphyr backend contract at the ingest
//! layer.
//!
//! The shared `yaml_options()` profile (crate-private, used by
//! `parse_raw_yaml`, subscription/proxy-provider/rule-set payload parsers)
//! is mirrored below so `serde_json::Value`-level semantics can be asserted
//! directly; document-level behaviour is additionally exercised through the
//! public ingest functions. Each test pins either a serde_norway parity the
//! options restore, or a residual divergence that is accepted, documented
//! behaviour (see CHANGELOG).

use meow_config::ListenerSpec;

/// Mirror of `crate::yaml_options()` — every untrusted-document ingest
/// point in `meow-config` parses under these options. The depth budget is
/// `meow_common::yaml::MAX_DEPTH`, the same shared constant the crate
/// uses, so the mirror cannot drift from the real profile.
fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        reject_unsupported_tags: true,
        ignore_binary_tag_for_string: true,
        non_finite_float_policy: serde_saphyr::NonFiniteFloatPolicy::PassThrough,
        budget: serde_saphyr::budget! { max_depth: meow_common::yaml::MAX_DEPTH },
    }
}

fn parse_value(doc: &str) -> Result<serde_json::Value, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(doc, yaml_options())
}

fn parse_value_err(doc: &str) -> String {
    parse_value(doc).unwrap_err().without_snippet().to_string()
}

/// YAML-1.1 boolean spellings must stay strings under `strict_booleans` —
/// the serde_norway semantics meow grew up with.
#[test]
fn yaml_11_bool_spellings_stay_strings() {
    for spelling in ["yes", "no", "on", "off", "y", "n"] {
        let v = parse_value(&format!("k: {spelling}")).unwrap();
        assert_eq!(
            v["k"].as_str(),
            Some(spelling),
            "`{spelling}` must resolve as a string, not a bool"
        );
    }
}

/// …and a `yes` on a typed `bool` field is a type error, not a coercion.
#[test]
fn yaml_11_bool_spelling_errors_on_bool_field() {
    // `ipv6: Option<bool>` — serde_norway errored the same way.
    let err = meow_config::parse_raw_yaml("ipv6: yes\n").unwrap_err();
    assert!(
        err.to_string().contains("bool"),
        "expected a bool-typed error, got: {err}"
    );
}

/// Residual divergence: saphyr case-folds the `true`/`false`/`null`
/// spellings (`TrUe` resolves as a bool) — diverging from *both*
/// serde_norway and yaml.v3 (mihomo), whose resolve tables only accept the
/// fixed `true`/`True`/`TRUE`-style spellings and keep these as strings.
/// Pinned as accepted behaviour.
#[test]
fn case_folded_bools_and_nulls_resolve() {
    let v = parse_value("k: TrUe").unwrap();
    assert_eq!(v["k"].as_bool(), Some(true));
    let v = parse_value("k: fAlSe").unwrap();
    assert_eq!(v["k"].as_bool(), Some(false));
    let v = parse_value("k: nUll").unwrap();
    assert_eq!(v, serde_json::json!({ "k": null }));
}

/// Residual divergence: a leading-zero decimal resolves as a float where
/// serde_norway kept the string (`0123` → `123.0`, not octal 83).
#[test]
fn leading_zero_decimals_resolve_as_floats() {
    let v = parse_value("k: 0123").unwrap();
    assert_eq!(v["k"].as_f64(), Some(123.0));
    let v = parse_value("k: -0123").unwrap();
    assert_eq!(v["k"].as_f64(), Some(-123.0));
}

/// `NonFiniteFloatPolicy::PassThrough` reproduces serde_norway's `.inf`/
/// `.nan` semantics: they map to `null` inside a `serde_json::Value`
/// subtree and to the IEEE values in a typed `f64`. An overflowing literal
/// (`1e999`) resolves to `null` the same way — serde_norway kept it a
/// string — pinned divergence (verified against serde-saphyr 2.0.0).
#[test]
fn non_finite_floats_pass_through() {
    for literal in [".inf", "-.inf", ".nan"] {
        let v = parse_value(&format!("k: {literal}")).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "k": null }),
            "`{literal}` must resolve to null in a Value subtree"
        );
    }

    #[derive(serde::Deserialize)]
    struct FloatHolder {
        k: f64,
    }
    let holder: FloatHolder =
        serde_saphyr::from_str_with_options("k: .inf", yaml_options()).unwrap();
    assert!(holder.k.is_infinite() && holder.k.is_sign_positive());

    let v = parse_value("k: 1e999").unwrap();
    assert_eq!(
        v,
        serde_json::json!({ "k": null }),
        "an overflowing float literal resolves to null like `.inf`, not a string"
    );
}

/// `DuplicateKeyPolicy::Error` is deliberate hardening over serde_norway's
/// silent last-wins.
#[test]
fn duplicate_keys_error() {
    let msg = parse_value_err("key: 1\nkey: 2\n");
    assert!(
        msg.to_lowercase().contains("duplicate"),
        "expected a duplicate-key error, got: {msg}"
    );
    // Same fail-closed behaviour through the shared ingest path.
    assert!(meow_config::parse_raw_yaml("mode: rule\nmode: global\n").is_err());
}

/// `reject_unsupported_tags` restores serde_norway's fail-closed contract:
/// a `!tag` node errors the document instead of silently detagging.
#[test]
fn unsupported_tag_fails_closed() {
    let msg = parse_value_err("key: !foo v\n");
    assert!(
        msg.to_lowercase().contains("tag"),
        "expected an unsupported-tag error, got: {msg}"
    );
}

/// A tagged proxy node anywhere in a subscription fails the whole document
/// (doc-level error under both strict and lenient) — hardening over the
/// norway era, where lenient mode only skipped the one entry.
#[test]
fn subscription_tagged_proxy_node_fails_document() {
    let doc = "proxies:\n  - name: a\n    type: http\n    server: !foo x\n    port: 1\n";
    for strict in [true, false] {
        let err = meow_config::subscription::parse_subscription_yaml(doc, strict)
            .err()
            .expect("a tagged node must fail the document");
        assert!(
            err.to_string().to_lowercase().contains("tag"),
            "strict={strict}: expected a tag error, got: {err}"
        );
    }
}

/// Lenient mode's per-entry skip semantics are unchanged for genuinely
/// malformed (non-tag) entries: a non-mapping `proxies:` item is warn-skipped.
#[test]
fn subscription_lenient_mode_still_skips_malformed_entries() {
    let doc = "proxies:\n  - 42\n  - name: ok\n    type: direct\n";
    let data = meow_config::subscription::parse_subscription_yaml(doc, false).unwrap();
    assert_eq!(data.proxies.len(), 1);
    assert_eq!(data.proxies[0]["name"].as_str(), Some("ok"));
    // The same doc is a hard error under strict.
    assert!(meow_config::subscription::parse_subscription_yaml(doc, true).is_err());
}

/// Both enum forms for `ListenerSpec` parse under *default* options: the
/// `!tproxy` tag form (what `!`-tagged YAML documents carry) and the map
/// form `{tproxy: …}` — the latter is a saphyr widening serde_norway
/// rejected, pinned here as accepted behaviour.
#[test]
fn listener_spec_accepts_tag_and_map_forms() {
    let spec: ListenerSpec = serde_saphyr::from_str("!tproxy\nsni: true\n").unwrap();
    assert!(matches!(spec, ListenerSpec::TProxy { sni: true, .. }));
    let spec: ListenerSpec = serde_saphyr::from_str("tproxy:\n  sni: true\n").unwrap();
    assert!(matches!(spec, ListenerSpec::TProxy { sni: true, .. }));
}

/// The `budget.max_depth` bound must trip inside the parser — saphyr's
/// `serde_json::Value` descend recurses one stack frame per level and would
/// overflow a caller's stack before the legacy 128-level pre-filter could
/// matter. These tests run in the debug build that hazard lives in: deep
/// docs must produce a clean error, never a crash.
#[test]
fn depth_budget_trips_before_stack_overflow() {
    // Depth counts each container level: a bare 32-deep flow sequence
    // parses, 33 errors with a `budget breached: Depth` — never a crash.
    // (A `k:` wrapper adds one level of its own.)
    let ok_flow = format!("{}{}", "[".repeat(32), "]".repeat(32));
    assert!(parse_value(&ok_flow).is_ok());
    for n in [33, 40, 100] {
        let deep_flow = format!("{}{}", "[".repeat(n), "]".repeat(n));
        let msg = parse_value_err(&deep_flow);
        assert!(
            msg.contains("budget breached") || msg.to_lowercase().contains("depth"),
            "{n}-deep flow must hit the depth budget, got: {msg}"
        );
    }

    // Same bound on block indentation: `root:` plus 31 nested `k:` maps is
    // depth 32 and parses; 32 nested `k:` maps is depth 33 and errors.
    let block = |levels: usize| {
        let mut doc = String::from("root:");
        for i in 0..levels {
            doc.push('\n');
            doc.push_str(&" ".repeat((i + 1) * 2));
            doc.push_str("k:");
        }
        doc.push_str(" 1");
        doc
    };
    assert!(parse_value(&block(31)).is_ok());
    let msg = parse_value_err(&block(32));
    assert!(
        msg.contains("budget breached") || msg.to_lowercase().contains("depth"),
        "33-deep block doc must hit the depth budget, got: {msg}"
    );
}

/// `MergeKeyPolicy::Merge` (the `yaml_options` default) replaces
/// `serde_yaml::Value::apply_merge` with identical precedence: explicit keys
/// win over merged ones, sequences of maps merge left-to-right, nested
/// merge keys inside merged maps resolve.
#[test]
fn merge_keys_expand_with_explicit_precedence() {
    let doc = r#"
defaults: &d
  server: example.com
  port: 443
  type: http
proxies:
  - <<: *d
    name: a
    port: 8080
  - <<: *d
    name: b
"#;
    let v = parse_value(doc).unwrap();
    let proxies = v["proxies"].as_array().unwrap();
    assert_eq!(proxies[0]["port"].as_u64(), Some(8080), "explicit wins");
    assert_eq!(proxies[0]["server"].as_str(), Some("example.com"));
    assert_eq!(proxies[0]["type"].as_str(), Some("http"));
    assert_eq!(proxies[1]["port"].as_u64(), Some(443), "merged default");
}

#[test]
fn merge_key_sequence_of_maps() {
    let doc = "a: &a\n  x: 1\nb: &b\n  y: 2\nm:\n  <<: [*a, *b]\n";
    let v = parse_value(doc).unwrap();
    assert_eq!(v["m"]["x"].as_u64(), Some(1));
    assert_eq!(v["m"]["y"].as_u64(), Some(2));
}

#[test]
fn merge_key_nested_anchor_resolves() {
    let doc = "base: &base\n  a: 1\nmid: &mid\n  <<: *base\n  b: 2\nm:\n  <<: *mid\n  c: 3\n";
    let v = parse_value(doc).unwrap();
    assert_eq!(v["m"]["a"].as_u64(), Some(1), "nested merge resolved");
    assert_eq!(v["m"]["b"].as_u64(), Some(2));
    assert_eq!(v["m"]["c"].as_u64(), Some(3));
}

#[test]
fn merge_key_invalid_value_errors() {
    // `<<:` on a non-mapping value is an invalid merge — serde_norway's
    // apply_merge errored identically.
    let msg = parse_value_err("m:\n  <<: 42\n");
    assert!(
        msg.to_lowercase().contains("merge"),
        "expected an invalid-merge-key error, got: {msg}"
    );
}

/// Residual divergence pinned per the migration review: serde_norway's
/// `apply_merge` errored on `<<: null`; saphyr's `MergeKeyPolicy::Merge`
/// silently merges nothing — the mapping stays empty. Accepted narrowing,
/// documented in CHANGELOG.
#[test]
fn merge_key_null_merges_to_empty_map() {
    let v = parse_value("m:\n  <<: null\n").unwrap();
    assert_eq!(
        v["m"],
        serde_json::json!({}),
        "`<<: null` must silently yield an empty map (norway errored)"
    );
}

/// Order pin on the repo's one order-sensitive map: `nameserver-policy`
/// is an `IndexMap` whose key order IS the lookup priority, so the
/// merge-key contract above must hold positionally, not just by value.
/// serde-saphyr expands `<<:` in the event stream — merged entries append
/// at the map tail wherever the `<<:` line sits, and an explicit key
/// keeps its written position and wins over a merged same-name key.
/// Asserted on `keys()` order through the production ingest (#802
/// semantics; mirrored in `docs/specs/dns-nameserver-policy.md`).
#[test]
fn nameserver_policy_mid_map_merge_key_appends_merged_at_tail() {
    let doc = r#"
x-nsp-defaults: &defaults
  "+.merged-a.example": 8.8.8.8
  "+.shared.example": 5.5.5.5
  "+.merged-b.example": 9.9.9.9
dns:
  nameserver-policy:
    "+.first.example": 1.1.1.1
    <<: *defaults
    "+.shared.example": 2.2.2.2
    "+.last.example": 3.3.3.3
"#;
    let raw = meow_config::parse_raw_yaml(doc).unwrap();
    let policy = raw.dns.unwrap().nameserver_policy.unwrap();
    let keys: Vec<&String> = policy.keys().collect();
    assert_eq!(
        keys,
        [
            "+.first.example",
            "+.shared.example",
            "+.last.example",
            "+.merged-a.example",
            "+.merged-b.example",
        ],
        "explicit keys keep written order; a mid-map `<<:` still lands its \
         merged entries at the tail"
    );
    // Explicit wins over the merged same-name key in its own slot.
    assert_eq!(policy["+.shared.example"].as_urls(), ["2.2.2.2"]);
}

/// Twin of the `nameserver-policy` pin above for the tree's second
/// order-semantic map: `hosts:` document order decides same-slot
/// collision winners, so the merge-key contract must hold positionally
/// here as well — explicit keys keep written positions, `<<:` entries
/// append at the map tail, and an explicit key wins over a merged
/// same-name key in its own slot. Asserted on `keys()` order through
/// the production ingest.
#[test]
fn hosts_mid_map_merge_key_appends_merged_at_tail() {
    let doc = r#"
x-hosts-defaults: &defaults
  "+.merged-a.example": 8.8.8.8
  "+.shared.example": 5.5.5.5
  "+.merged-b.example": 9.9.9.9
hosts:
  "+.first.example": 1.1.1.1
  <<: *defaults
  "+.shared.example": 2.2.2.2
  "+.last.example": 3.3.3.3
"#;
    let raw = meow_config::parse_raw_yaml(doc).unwrap();
    let hosts = raw.hosts.unwrap();
    let keys: Vec<&String> = hosts.keys().collect();
    assert_eq!(
        keys,
        [
            "+.first.example",
            "+.shared.example",
            "+.last.example",
            "+.merged-a.example",
            "+.merged-b.example",
        ],
        "explicit keys keep written order; a mid-map `<<:` still lands its \
         merged entries at the tail"
    );
    // Explicit wins over the merged same-name key in its own slot.
    assert_eq!(hosts["+.shared.example"].as_slice(), ["2.2.2.2"]);
}

/// Regression for the production stack overflow (serde-saphyr migration
/// review, F1): the shipped `meow`/`meow-cli` binaries parse on a 1 MiB
/// main thread already ~350-400 KiB deep in async-poll frames, where the
/// descend's ≈26 KiB/level debug cost overflows at document depth ≈25 —
/// *below* the `MAX_DEPTH` budget that exists to trip first. `cargo test`
/// runs each test on an 8 MiB stack, so this test re-creates the
/// production stack context directly: a caller thread with a 1 MiB stack
/// (the Windows main-thread reserve the binaries ship with) and ~480 KiB
/// of it already burned before the public ingest runs.
///
/// With the fix this passes because `parse_raw_yaml` pushes the descend
/// onto its own `PARSE_STACK_SIZE` thread. Should the ingest ever move
/// back onto the caller's stack, the restricted caller overflows the same
/// way the binary did and the test process dies — the regression cannot
/// pass silently.
#[test]
fn deep_documents_error_not_abort_on_a_production_sized_stack() {
    /// The shipped binaries' main-thread stack reserve: 1 MiB.
    const CALLER_STACK: usize = 1 << 20;
    /// Stack burned before parsing, standing in for the async-poll frame
    /// chain `meow -t` / startup sit under when `parse_raw_yaml` runs.
    const CALLER_FRAMES: usize = 480 * 1024;

    /// Consume `budget` bytes of stack in ~4 KiB frames, then run the real
    /// ingest — `#[inline(never)]` recursion plus a black_box'd array keeps
    /// every frame alive down to the parse call.
    #[inline(never)]
    fn burn_then_parse(
        budget: usize,
        doc: &str,
    ) -> Result<meow_config::raw::RawConfig, anyhow::Error> {
        let mut frame = [0u8; 4096];
        frame[0] = (budget & 0xff) as u8;
        std::hint::black_box(&mut frame);
        if budget > frame.len() {
            burn_then_parse(budget - frame.len(), doc)
        } else {
            meow_config::parse_raw_yaml(doc)
        }
    }

    // `a:` + nested `k:` maps at one-space indents — the same block-mapping
    // shape the review crashed on; `levels` is the document's total depth.
    let doc = |levels: usize| {
        let mut doc = String::from("a:");
        for i in 1..levels {
            doc.push('\n');
            doc.push_str(&" ".repeat(i));
            doc.push_str("k:");
        }
        doc.push('\n');
        doc.push_str(&" ".repeat(levels));
        doc.push_str("v: 1");
        doc
    };

    eprintln!(
        "caller stack budget: {CALLER_STACK} bytes, {CALLER_FRAMES} pre-burned — \
         the 1 MiB main-thread + async-frame context the production overflow lived in"
    );
    for (levels, expect_ok) in [(25, true), (30, true), (40, false), (100, false)] {
        let document = doc(levels);
        // Parse through the production ingest on the restricted stack. A
        // pre-fix build overflows this thread ≈depth 20-25 and aborts the
        // test binary; a correct build returns a plain `Result`.
        let result = std::thread::Builder::new()
            .name(format!("yaml-depth-{levels}"))
            .stack_size(CALLER_STACK)
            .spawn(move || burn_then_parse(CALLER_FRAMES, &document))
            .expect("spawn restricted-stack caller")
            .join()
            .expect("restricted-stack caller panicked");
        match (result, expect_ok) {
            (Ok(_), true) => {}
            (Ok(_), false) => {
                panic!("depth-{levels} document parsed — the depth budget did not trip")
            }
            (Err(e), true) => {
                panic!("depth-{levels} document must parse cleanly, got: {e:#}")
            }
            (Err(e), false) => assert!(
                format!("{e:#}").to_lowercase().contains("depth"),
                "depth-{levels} document must fail on the depth bound, got: {e:#}"
            ),
        }
    }
}

/// A `!!binary`-tagged scalar delivers as a plain string under
/// `ignore_binary_tag_for_string` — serde_norway delivered it as a
/// `Value::String` too.
#[test]
fn binary_tagged_scalar_delivers_as_string() {
    let v = parse_value("k: !!binary aGk=\n").unwrap();
    assert!(
        v["k"].is_string(),
        "a !!binary scalar must reach Value as a string, got: {v}"
    );
}

/// Pins the single-pass `parse_raw_yaml` (`Spanned<YamlNode>` tree +
/// the crate's typed `Deserializer`) contract: empty / null documents
/// normalize to an empty root mapping, and a single document carrying
/// both `hosts` and `dns.nameserver-policy` (each with
/// reverse-lexicographical keys and mid-map `<<:` merges) alongside
/// `tun`, `sniffer`, and `listeners` sub-tables preserves both
/// `IndexMap`s' exact YAML key order and all sibling fields.
#[test]
fn parse_raw_yaml_typed_tree_preserves_empty_doc_and_ordered_maps_together() {
    for empty in ["", "null\n"] {
        let raw = meow_config::parse_raw_yaml(empty)
            .unwrap_or_else(|e| panic!("empty/null doc {empty:?} must parse: {e}"));
        assert!(raw.mixed_port.is_none());
        assert!(raw.hosts.is_none());
        assert!(raw.dns.is_none());
        assert!(raw.tun.is_none());
        assert!(raw.sniffer.is_none());
        assert!(raw.listeners.is_none());
    }

    let doc = r#"
mixed-port: 7890
mode: rule
x-hosts-base: &hbase
  "m-merged.example": 10.0.0.9
  "k-shared.example": 10.0.0.8
x-nsp-base: &nbase
  "+.m-merged.example": 9.9.9.9
  "+.k-shared.example": [4.4.4.4, 8.8.4.4]
hosts:
  "z-first.example": 10.0.0.1
  <<: *hbase
  "k-shared.example": [10.0.0.2, 10.0.0.3]
  "a-last.example": 10.0.0.4
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
  nameserver-policy:
    "+.z-first.example": 1.0.0.1
    <<: *nbase
    "+.k-shared.example": 2.2.2.2
    "+.a-last.example": [3.3.3.3, 8.8.8.8]
tun:
  enable: true
  device: meow0
  mtu: 1400
sniffer:
  enable: true
  timeout: 150
  override-destination: true
listeners:
  - name: in-mixed
    type: mixed
    port: 17890
"#;
    let raw = meow_config::parse_raw_yaml(doc).unwrap();
    assert_eq!(raw.mixed_port, Some(7890));
    assert_eq!(raw.mode.as_deref(), Some("rule"));

    let hosts = raw.hosts.expect("hosts present");
    let host_keys: Vec<&str> = hosts.keys().map(String::as_str).collect();
    assert_eq!(
        host_keys,
        [
            "z-first.example",
            "k-shared.example",
            "a-last.example",
            "m-merged.example",
        ],
        "hosts must keep YAML order (not BTreeMap lexicographical order)"
    );
    assert_eq!(
        hosts["k-shared.example"].as_slice(),
        ["10.0.0.2", "10.0.0.3"]
    );
    assert_eq!(hosts["m-merged.example"].as_slice(), ["10.0.0.9"]);

    let dns = raw.dns.expect("dns present");
    assert_eq!(dns.enable, Some(true));
    assert_eq!(dns.enhanced_mode.as_deref(), Some("fake-ip"));
    let nsp = dns.nameserver_policy.expect("nameserver-policy present");
    let nsp_keys: Vec<&str> = nsp.keys().map(String::as_str).collect();
    assert_eq!(
        nsp_keys,
        [
            "+.z-first.example",
            "+.k-shared.example",
            "+.a-last.example",
            "+.m-merged.example",
        ],
        "nameserver-policy must keep YAML order (not BTreeMap lexicographical order)"
    );
    assert_eq!(nsp["+.k-shared.example"].as_urls(), ["2.2.2.2"]);
    assert_eq!(nsp["+.a-last.example"].as_urls(), ["3.3.3.3", "8.8.8.8"]);

    let tun = raw.tun.expect("tun present");
    assert!(tun.enable);
    assert_eq!(tun.device.as_deref(), Some("meow0"));
    assert_eq!(tun.mtu, Some(1400));

    let sniffer = raw.sniffer.expect("sniffer present");
    assert_eq!(sniffer.enable, Some(true));
    assert_eq!(sniffer.timeout, Some(150));
    assert_eq!(sniffer.override_destination, Some(true));

    let listeners = raw.listeners.expect("listeners present");
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].name, "in-mixed");
    assert_eq!(listeners[0].listener_type, "mixed");
    assert_eq!(listeners[0].port, Some(17890));
}

// ── PR #827 review pins ──────────────────────────────────────────────────
// The `serde_saphyr → serde_json::Value → from_value` staging lost five
// behaviours the direct `RawConfig` path had. The `Spanned<YamlNode>` tree
// + handwritten deserializer that replaced it must restore all of them.

/// Review finding 3 (positional fill): `serde_json::from_value` accepted
/// a top-level *sequence* whose element count matched `RawConfig`'s field
/// count — the exact `[null,7891,null×38]` vector filled the struct
/// positionally. The tree deserializer's `deserialize_struct` accepts
/// only mappings, so the vector — and any nested sequence where a struct
/// is expected — is a hard `expected mapping start` error again.
#[test]
fn top_level_sequence_cannot_fill_raw_config_positionally() {
    let mut doc = String::from("[null,7891");
    for _ in 0..38 {
        doc.push_str(",null");
    }
    doc.push(']');
    let err = meow_config::parse_raw_yaml(&doc).unwrap_err().to_string();
    assert!(
        err.contains("expected mapping"),
        "a top-level sequence must not fill RawConfig positionally, got: {err}"
    );

    // A nested sequence where a struct belongs errors the same way —
    // `dns:` is an `Option<RawDns>`, not a list.
    let err = meow_config::parse_raw_yaml("dns:\n  - enable\n  - 1.1.1.1\n")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expected mapping") && err.contains("dns"),
        "a sequence under a struct field must error naming the field, got: {err}"
    );
}

/// Review finding 2 (scalar type context): saphyr's typed methods parsed
/// the scalar's *text*, so quoted scalars reach numeric/bool targets and
/// resolved scalars coerce to text. The tree deserializer keeps the same
/// contract.
#[test]
fn scalar_coercions_match_the_direct_path() {
    let raw =
        meow_config::parse_raw_yaml("secret: 123456\nport: \"7890\"\nipv6: \"true\"\n").unwrap();
    assert_eq!(raw.secret.as_deref(), Some("123456"), "int → string");
    assert_eq!(raw.port, Some(7890), "quoted int → u16");
    assert_eq!(raw.ipv6, Some(true), "quoted bool → bool");

    let raw = meow_config::parse_raw_yaml("tun:\n  mtu: \"1400\"\n").unwrap();
    assert_eq!(raw.tun.unwrap().mtu, Some(1400), "quoted int → Option<u16>");

    // Radix literals behave the same quoted and bare: `0x10` resolves to
    // int 16; `"0x10"` parses its text through the same radix table.
    assert_eq!(
        meow_config::parse_raw_yaml("port: 0x10\n").unwrap().port,
        Some(16)
    );
    assert_eq!(
        meow_config::parse_raw_yaml("port: \"0x10\"\n")
            .unwrap()
            .port,
        Some(16)
    );

    // …and every text that the direct path's int/bool parsers rejected
    // still rejects: floats never coerce to ints, non-bool text fails
    // strict booleans, and out-of-range ints error.
    let err = meow_config::parse_raw_yaml("tun:\n  mtu: 1500.0\n")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid u16"),
        "float → u16 must fail, got: {err}"
    );
    let err = meow_config::parse_raw_yaml("ipv6: \"on\"\n")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid boolean (strict mode expects true/false)"),
        "quoted non-bool must fail strict booleans, got: {err}"
    );
    for doc in ["port: -5\n", "port: 70000\n", "port: 1_0_0_x\n"] {
        assert!(
            meow_config::parse_raw_yaml(doc).is_err(),
            "{doc:?} must be an invalid u16"
        );
    }
}

/// Review finding 1 (non-finite collapse): under the `serde_json::Value`
/// stage `.inf`/`.nan`/`1e999` became `Value::Null`, so `Option<u16>:
/// .inf` silently deserialized to `None`. The tree keeps them `Float`
/// nodes: a typed scalar target errors `invalid <ty>` — the direct
/// path's verdict — and only a `serde_json::Value` field still flattens
/// them to `null` (that visitor's own semantics).
///
/// (`Option<String>` legitimately *accepts* the literal — the direct path
/// delivered `.inf` as the string `".inf"`, and the tree delivers the same
/// source spelling. No `f64` field exists in `RawConfig`, so the typed-`f64`
/// acceptance leg is covered by `non_finite_floats_pass_through` above.)
#[test]
fn non_finite_floats_error_on_typed_option_fields() {
    for literal in [".inf", "-.inf", ".nan", "1e999"] {
        for (doc, ty) in [
            (format!("port: {literal}\n"), "u16"),
            (format!("ipv6: {literal}\n"), "boolean"),
            (format!("tun:\n  mtu: {literal}\n"), "u16"),
        ] {
            let err = meow_config::parse_raw_yaml(&doc).unwrap_err().to_string();
            assert!(
                err.contains(&format!("invalid {ty}")),
                "`{literal}` into Option<{ty}> must error, got: {err}"
            );
        }
        // The direct-path behaviour for string targets, kept.
        let raw = meow_config::parse_raw_yaml(&format!("secret: {literal}\n")).unwrap();
        assert_eq!(
            raw.secret.as_deref(),
            Some(literal),
            "`secret: {literal}` delivers its source spelling, as the direct path did"
        );
        // And the `serde_json::Value` capture fields still flatten.
        let raw = meow_config::parse_raw_yaml(&format!("firewall: {literal}\n")).unwrap();
        assert_eq!(raw.firewall, Some(serde_json::Value::Null));
    }
}

/// The `IndexMap` order is now the tree's own document order — no overlay
/// pass exists. Single-sided pins prove each map preserves order without
/// the other present.
#[test]
fn hosts_only_preserves_document_order() {
    let raw = meow_config::parse_raw_yaml(
        "hosts:\n  \"z-first.example\": 1.1.1.1\n  \"a-second.example\": 2.2.2.2\n  \"m-last.example\": 3.3.3.3\n",
    )
    .unwrap();
    let hosts = raw.hosts.unwrap();
    let keys: Vec<&str> = hosts.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["z-first.example", "a-second.example", "m-last.example"]
    );
}

#[test]
fn nameserver_policy_only_preserves_document_order() {
    let raw = meow_config::parse_raw_yaml(
        "dns:\n  nameserver-policy:\n    \"+.z-first.example\": 1.1.1.1\n    \"+.a-second.example\": 2.2.2.2\n    \"+.m-last.example\": [3.3.3.3, 8.8.8.8]\n",
    )
    .unwrap();
    let nsp = raw.dns.unwrap().nameserver_policy.unwrap();
    let keys: Vec<&str> = nsp.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "+.z-first.example",
            "+.a-second.example",
            "+.m-last.example"
        ]
    );
    assert_eq!(nsp["+.m-last.example"].as_urls(), ["3.3.3.3", "8.8.8.8"]);
}

/// JSON text is legal YAML 1.2: a flow document now keeps its written key
/// order in `hosts`/`nameserver-policy` — something the
/// `serde_json::Value` stage's `BTreeMap` sorted away. (The production
/// `--config-string` path accepts JSON payloads this way.)
#[test]
fn json_flow_document_preserves_hosts_and_policy_order() {
    let doc = concat!(
        "{\"hosts\": {\"z.example\": \"1.1.1.1\", \"a.example\": \"2.2.2.2\"},",
        " \"dns\": {\"nameserver-policy\": {\"+.z.example\": \"8.8.8.8\",",
        " \"+.a.example\": [\"9.9.9.9\", \"4.4.4.4\"]}},",
        " \"mixed-port\": 7890}"
    );
    let raw = meow_config::parse_raw_yaml(doc).unwrap();
    let hosts = raw.hosts.unwrap();
    let host_keys: Vec<&str> = hosts.keys().map(String::as_str).collect();
    assert_eq!(host_keys, ["z.example", "a.example"]);
    let nsp = raw.dns.unwrap().nameserver_policy.unwrap();
    let nsp_keys: Vec<&str> = nsp.keys().map(String::as_str).collect();
    assert_eq!(nsp_keys, ["+.z.example", "+.a.example"]);
    assert_eq!(raw.mixed_port, Some(7890));
}

/// Empty/null spellings for the order-sensitive fields: `~`/absent value
/// → `None`; `{}` → an *empty but present* map — the direct path's exact
/// verdicts (an empty map is not null).
#[test]
fn empty_and_null_forms_for_ordered_fields() {
    for doc in [
        "hosts: ~\n",
        "hosts:\n",
        "hosts: null\n",
        "dns:\n  nameserver-policy: ~\n",
        "dns:\n  nameserver-policy:\n",
    ] {
        let raw =
            meow_config::parse_raw_yaml(doc).unwrap_or_else(|e| panic!("{doc:?} must parse: {e}"));
        assert!(raw.hosts.is_none(), "{doc:?}: hosts must be None");
        if let Some(dns) = raw.dns.as_ref() {
            assert!(
                dns.nameserver_policy.is_none(),
                "{doc:?}: nameserver-policy must be None"
            );
        }
    }

    let raw = meow_config::parse_raw_yaml("hosts: {}\n").unwrap();
    assert_eq!(
        raw.hosts.unwrap().len(),
        0,
        "empty hosts map is Some(empty)"
    );
    let raw = meow_config::parse_raw_yaml("dns:\n  nameserver-policy: {}\n").unwrap();
    let nsp = raw.dns.unwrap().nameserver_policy.unwrap();
    assert_eq!(nsp.len(), 0, "empty nameserver-policy is Some(empty)");

    // A null `dns:` itself is a plain absent section.
    let raw = meow_config::parse_raw_yaml("dns: null\n").unwrap();
    assert!(raw.dns.is_none());
}

/// Review finding 4 (diagnostics): typed errors carry the leaf node's
/// `line/column` plus the dotted field path accumulated through nested
/// map values — `line 3 column 12: dns.fallback-filter.geoip: invalid
/// boolean (strict mode expects true/false)`.
#[test]
fn typed_errors_carry_line_column_and_field_path() {
    let doc = "dns:\n  fallback-filter:\n    geoip: maybe\n";
    let err = meow_config::parse_raw_yaml(doc).unwrap_err().to_string();
    assert!(
        err.contains("line 3 column 12") && err.contains("dns.fallback-filter.geoip"),
        "expected `line 3 column 12: dns.fallback-filter.geoip: …`, got: {err}"
    );
    assert!(err.contains("invalid boolean"), "got: {err}");

    // Sequence indices fuse onto the segment: `listeners[0].port`
    // (`proxies:` entries stay untyped `serde_json::Value` maps, so the
    // pin uses a typed `RawListener` element).
    let doc = "listeners:\n  - name: l\n    type: mixed\n    port: nope\n";
    let err = meow_config::parse_raw_yaml(doc).unwrap_err().to_string();
    assert!(
        err.contains("listeners[0].port") && err.contains("invalid u16"),
        "expected the `[i]`-indexed field path, got: {err}"
    );
}

/// The same leaf location on a top-level scalar: `port: abc` reports the
/// value's column — `line 3 column 7: port: invalid u16`.
#[test]
fn top_level_scalar_error_reports_value_column() {
    let doc = "mixed-port: 7890\nmode: rule\nport: abc\n";
    let err = meow_config::parse_raw_yaml(doc).unwrap_err().to_string();
    assert!(
        err.contains("line 3 column 7") && err.contains("port") && err.contains("invalid u16"),
        "expected `line 3 column 7: port: invalid u16`, got: {err}"
    );
}

/// Non-string scalar keys into a `String`-keyed map get the key's source
/// spelling, as on the direct path (`0x1F` stays `"0x1F"`, not `"31"`). A
/// null key errors on both paths.
#[test]
fn scalar_map_keys_keep_source_text() {
    let doc = "hosts:\n  123: 1.1.1.1\n  ~: 2.2.2.2\n";
    let err = meow_config::parse_raw_yaml(doc).unwrap_err().to_string();
    assert!(
        err.contains("null"),
        "a `~` key must fail like the direct path's NullIntoString, got: {err}"
    );

    let raw = meow_config::parse_raw_yaml(
        "hosts:\n  123: 1.1.1.1\n  plain.example: 2.2.2.2\n  0x1F: 3.3.3.3\n  +7: 4.4.4.4\n",
    )
    .unwrap();
    let hosts = raw.hosts.unwrap();
    let keys: Vec<&str> = hosts.keys().map(String::as_str).collect();
    assert_eq!(keys, ["123", "plain.example", "0x1F", "+7"]);
}

/// Two keys saphyr's resolved-value dedup tells apart can still read as
/// the same string — `1` (an int) and `"1"`. The tree's
/// `IndexMap<String, _>` target would let the second silently overwrite
/// the first, so the document is rejected instead — an intentional
/// narrowing. Distinct spellings of one value (`TrUe`/`"true"`,
/// `1.0`/`"1"`) are distinct strings and stay two keys, as on the direct
/// path.
#[test]
fn same_string_key_collision_is_an_error() {
    for doc in [
        "hosts:\n  1: 1.1.1.1\n  \"1\": 2.2.2.2\n",
        "dns:\n  nameserver-policy:\n    0x1F: 1.1.1.1\n    \"0x1F\": 2.2.2.2\n",
    ] {
        let err = meow_config::parse_raw_yaml(doc).unwrap_err().to_string();
        assert!(
            err.contains("duplicate mapping key"),
            "{doc:?} must fail as a same-string duplicate, got: {err}"
        );
    }

    let raw =
        meow_config::parse_raw_yaml("hosts:\n  TrUe: 1.1.1.1\n  \"true\": 2.2.2.2\n").unwrap();
    let hosts = raw.hosts.unwrap();
    assert_eq!(
        hosts.keys().map(String::as_str).collect::<Vec<_>>(),
        ["TrUe", "true"]
    );
    let raw = meow_config::parse_raw_yaml(
        "dns:\n  nameserver-policy:\n    1.0: 1.1.1.1\n    \"1\": 2.2.2.2\n",
    )
    .unwrap();
    let policy = raw.dns.unwrap().nameserver_policy.unwrap();
    assert_eq!(
        policy.keys().map(String::as_str).collect::<Vec<_>>(),
        ["1.0", "1"]
    );
}

/// PR #827 review: an unquoted value that YAML resolves to a number or
/// bool reaches a `String` field as it was written. A rewritten listener
/// password or API secret would lock clients out, and `filter: 01` is not
/// the regex `1`.
#[test]
fn number_like_strings_keep_source_text() {
    let doc = "\
secret: 012345
listeners:
  - name: ss-in
    type: shadowsocks
    port: 8388
    listen: 127.0.0.1
    cipher: aes-128-gcm
    password: 000000
  - name: ss-in2
    type: shadowsocks
    port: 8389
    listen: 127.0.0.1
    cipher: aes-128-gcm
    password: 123e4567
  - name: &n 0123
    type: shadowsocks
    port: 8390
    listen: 127.0.0.1
    cipher: aes-128-gcm
    password: *n
proxy-groups:
  - name: g
    type: select
    proxies: [DIRECT]
    filter: 01
    exclude-filter: 0x1F
";
    let raw = meow_config::parse_raw_yaml(doc).unwrap();
    assert_eq!(raw.secret.as_deref(), Some("012345"));
    let passwords: Vec<Option<&str>> = raw
        .listeners
        .as_deref()
        .unwrap()
        .iter()
        .map(|l| l.password.as_deref())
        .collect();
    assert_eq!(
        passwords,
        [Some("000000"), Some("123e4567"), Some("0123")],
        "an alias delivers its anchor's spelling"
    );
    let group = &raw.proxy_groups.as_deref().unwrap()[0];
    assert_eq!(group.filter.as_deref(), Some("01"));
    assert_eq!(group.exclude_filter.as_deref(), Some("0x1F"));
}

/// PR #827 review: an error raised by serde's own visitor (no
/// `HostsValue` variant matches) points at the value, not at its key.
#[test]
fn visitor_error_points_at_the_value() {
    let err = meow_config::parse_raw_yaml("mode: rule\nhosts:\n  a.example: [1, 2]\n")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("line 3 column 14") && err.contains("hosts.a.example"),
        "expected `line 3 column 14: hosts.a.example: …`, got: {err}"
    );
}
