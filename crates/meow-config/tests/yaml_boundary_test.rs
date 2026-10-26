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
