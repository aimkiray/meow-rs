//! A config load must fail on an entry it cannot build, not warn and keep
//! going (issue #513).
//!
//! Upstream mihomo drops the offending proxy, group, or rule with a warning and
//! loads everything else, so the rebuild reports success while the policy in
//! memory is not the policy on disk: every rule naming the dropped entry now
//! has no target, and a dropped rule hands its traffic to whatever comes next —
//! usually `MATCH,DIRECT`. These tests pin the rust-port behaviour: fail the
//! load and name the entry that caused it.

use meow_config::raw::RawConfig;

fn load(yaml: &str) -> Result<(usize, Vec<String>), String> {
    let raw: RawConfig = serde_yaml::from_str(yaml).expect("test yaml must deserialize");
    meow_config::rebuild_from_raw(&raw)
        .map(|(proxies, rules)| {
            let mut names: Vec<String> = proxies
                .keys()
                .map(std::string::ToString::to_string)
                .collect();
            names.sort();
            (rules.len(), names)
        })
        .map_err(|e| e.to_string())
}

fn load_error(yaml: &str) -> String {
    match load(yaml) {
        Ok((rules, names)) => {
            panic!("this config must not load — got {rules} rules and registry {names:?}")
        }
        Err(e) => e,
    }
}

#[test]
fn an_unbuildable_proxy_fails_the_load_and_names_itself() {
    let err = load_error(
        r#"
mode: rule
proxies:
  - name: good
    type: trojan
    server: 127.0.0.1
    port: 443
    password: x
  - name: broken
    type: trojan
    server: 127.0.0.1
    port: not-a-number
    password: x
rules:
  - MATCH,DIRECT
"#,
    );
    assert!(err.contains("broken"), "must name the proxy: {err}");
}

#[test]
fn an_unbuildable_group_fails_the_load_and_names_itself() {
    let err = load_error(
        r#"
mode: rule
proxies:
  - name: node
    type: trojan
    server: 127.0.0.1
    port: 443
    password: x
proxy-groups:
  - name: broken-group
    type: not-a-group-type
    proxies:
      - node
rules:
  - MATCH,DIRECT
"#,
    );
    assert!(err.contains("broken-group"), "must name the group: {err}");
}

#[test]
fn an_unparseable_rule_fails_the_load_and_quotes_the_line() {
    let err = load_error(
        r#"
mode: rule
rules:
  - THIS-IS-NOT-A-RULE,DIRECT
  - MATCH,DIRECT
"#,
    );
    assert!(
        err.contains("THIS-IS-NOT-A-RULE,DIRECT"),
        "must quote the offending line: {err}"
    );
}

#[test]
fn a_rule_naming_an_undefined_sub_rule_block_fails_the_load() {
    // `parse_rules_full` now hard-fails on any line it cannot parse, which
    // covers the undefined-block case a separate promotion pass used to.
    let err = load_error(
        r#"
mode: rule
rules:
  - SUB-RULE,never-defined
  - MATCH,DIRECT
"#,
    );
    assert!(
        err.contains("never-defined"),
        "must name the missing sub-rule block: {err}"
    );
}

#[test]
fn a_config_where_every_entry_builds_still_loads() {
    let (rules, names) = load(
        r#"
mode: rule
proxies:
  - name: node
    type: trojan
    server: 127.0.0.1
    port: 443
    password: x
proxy-groups:
  - name: select-group
    type: select
    proxies:
      - node
      - DIRECT
rules:
  - DOMAIN,example.com,select-group
  - MATCH,DIRECT
"#,
    )
    .expect("a fully valid config must load");
    assert_eq!(rules, 2, "both rule lines must survive");
    assert!(names.iter().any(|n| n == "node"), "registry: {names:?}");
    assert!(
        names.iter().any(|n| n == "select-group"),
        "registry: {names:?}"
    );
}

#[test]
fn a_group_missing_one_member_still_builds() {
    // The leniency that stays: a group naming a proxy this config does not
    // have is upstream behaviour, not an unbuildable entry. Dropping the whole
    // group over one absent member would take the rest of the policy with it.
    let (_rules, names) = load(
        r#"
mode: rule
proxies:
  - name: node
    type: trojan
    server: 127.0.0.1
    port: 443
    password: x
proxy-groups:
  - name: partial
    type: select
    proxies:
      - node
      - gone-with-the-wind
rules:
  - MATCH,partial
"#,
    )
    .expect("a group with one absent member must still build");
    assert!(names.iter().any(|n| n == "partial"), "registry: {names:?}");
}
