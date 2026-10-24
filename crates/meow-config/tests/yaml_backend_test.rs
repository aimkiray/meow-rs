//! Guardrail for the YAML backend (issue #771, RUSTSEC-2024-0449).
//!
//! The workspace's YAML backend is `serde-saphyr` (crate path
//! `serde_saphyr`): a pure-Rust serde implementation over the
//! `granit-parser` event parser with `#![forbid(unsafe_code)]` — no
//! libyaml-descended crate remains in the dependency tree. It replaces the
//! earlier `serde_norway`-under-`serde_yaml` fork arrangement, which itself
//! only existed because `unsafe-libyaml` (the c2rust libyaml translation)
//! was archived by its author in 2024 (RUSTSEC-2024-0449).
//!
//! This test pins that arrangement at the *lockfile* level. `Cargo.lock`
//! is the single artefact that covers every workspace member, every
//! dependency kind (normal, dev, build), every platform-specific table and
//! the full transitive closure — where a `cargo tree` invocation sees only
//! one member's subtree under one edge set. Any `cargo update` or new
//! dependency that pulls a libyaml crate back is written into the lock, so
//! reading it directly (no cargo subprocess) is both the strictest and the
//! cheapest check: every libyaml/fork crate must be absent and
//! `serde-saphyr` must be present.
//!
//! A second, complementary assertion pins the *public API* boundary: the
//! value type `meow-config` hands to embedders is `serde_json::Value`, so
//! `serde_saphyr` stays an internal parse backend and swapping it again
//! stops being a breaking change. `public_api_names_no_yaml_backend_types`
//! scans every `src/*.rs` and tracks `pub` items across the multi-line
//! signatures this crate writes one-parameter-per-line, flagging any
//! `serde_yaml::`, `serde_norway::`, or `serde_saphyr::` inside one — none
//! may exist.

use std::fs;
use std::path::{Path, PathBuf};

/// YAML packages the lockfile must never contain: the archived `serde_yaml`
/// / `unsafe-libyaml` pair (RUSTSEC-2024-0449) and the `serde_norway` /
/// `unsafe-libyaml-norway` fork arrangement this migration replaced.
const FORBIDDEN_PACKAGES: &[&str] = &[
    "serde_yaml",
    "unsafe-libyaml",
    "serde_norway",
    "unsafe-libyaml-norway",
];

/// Packages proving the migration actually landed: `serde-saphyr` is the
/// backend and `granit-parser` its event parser — presence in the lock
/// means YAML support was swapped, not dropped.
const REQUIRED_PACKAGES: &[&str] = &["serde-saphyr", "granit-parser"];

/// Locate the workspace root: the nearest ancestor of this crate's
/// manifest dir that holds both `Cargo.lock` and a `Cargo.toml` containing
/// a `[workspace]` table. Panics when the markers never appear — a test
/// that cannot find the lock must fail loudly, not vacuously pass.
fn workspace_root() -> PathBuf {
    let start = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in start.ancestors() {
        if !dir.join("Cargo.lock").is_file() {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        let Ok(toml) = fs::read_to_string(&manifest) else {
            continue;
        };
        if toml.lines().any(|line| line.trim() == "[workspace]") {
            return dir.to_path_buf();
        }
    }
    panic!(
        "workspace root not found walking up from {}: no ancestor holds \
         both Cargo.lock and a [workspace] Cargo.toml",
        start.display()
    );
}

/// Whether `lock` holds a `[[package]]` stanza literally named `pkg`.
///
/// In lockfile format a package entry is the key-value line
/// `name = "PKG"` *inside a `[[package]]` stanza*. The same key shape
/// also appears under `[[patch.unused]]`, which lists `[patch]` entries
/// cargo resolved as unused — an unused patch never enters the
/// dependency graph, so a `name = "PKG"` line there must not satisfy or
/// trip the package check. The matcher therefore tracks section
/// headers: it only honours `name =` lines while inside a `[[package]]`
/// table and leaves that stanza at the next `[`-prefixed header
/// (`[metadata]`, `[[patch.unused]]`, the next `[[package]]`, …).
/// Indented `dependencies = […]` items never start with `[`, so the
/// header test cannot confuse a dep list for a stanza boundary.
///
/// Meanwhile `dependencies = […]` lists reference packages as
/// bare-string items like `"PKG",` (or `"PKG v1.2.3 (…)"`), so a
/// trimmed whole-line match on `name = "PKG"` stays immune to both
/// remaining false shapes: a dep-list mention cannot satisfy or trip
/// the package check, and a longer package name containing `pkg` as a
/// prefix (`unsafe-libyaml-norway` vs `unsafe-libyaml`) cannot match
/// accidentally.
fn lock_has_package(lock: &str, pkg: &str) -> bool {
    let entry = format!("name = \"{pkg}\"");
    let mut in_package = false;
    lock.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[[package]]";
            return false;
        }
        in_package && line == entry
    })
}

#[test]
fn yaml_backend_is_serde_saphyr() {
    let lock_path = workspace_root().join("Cargo.lock");
    let lock = fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));

    for pkg in FORBIDDEN_PACKAGES {
        assert!(
            !lock_has_package(&lock, pkg),
            "Cargo.lock must not contain `{pkg}`: libyaml-descended crates \
             (RUSTSEC-2024-0449 lineage) were removed wholesale by the \
             serde-saphyr migration. A dependency change or `cargo update` \
             pulled one back — revert it before merging."
        );
    }

    for pkg in REQUIRED_PACKAGES {
        assert!(
            lock_has_package(&lock, pkg),
            "Cargo.lock must contain `{pkg}`: serde-saphyr is the YAML \
             backend and granit-parser its event parser — the migration \
             did not land as expected."
        );
    }
}

/// `lock_has_package` must recognise `[[package]]` stanza keys only: the
/// same name inside a `dependencies` list is a reference, not a package,
/// a `name =` line inside `[[patch.unused]]` names a declared-but-unused
/// `[patch]` replacement rather than a linked package, and a longer name
/// containing the needle must not match.
#[test]
fn lock_package_matcher_is_exact() {
    // A pure-legacy lock flags both archived crates.
    let legacy_lock = "\
[[package]]
name = \"serde_yaml\"
version = \"0.9.34\"
dependencies = [
 \"unsafe-libyaml\",
]

[[package]]
name = \"unsafe-libyaml\"
version = \"0.2.11\"
";
    assert!(lock_has_package(legacy_lock, "serde_yaml"));
    assert!(lock_has_package(legacy_lock, "unsafe-libyaml"));

    // A norway-era lock flags its fork crates too — the fork arrangement
    // that used to satisfy this guard is now itself forbidden.
    let norway_lock = "\
[[package]]
name = \"serde_norway\"
version = \"0.9.42\"
dependencies = [
 \"unsafe-libyaml-norway\",
]

[[package]]
name = \"unsafe-libyaml-norway\"
version = \"0.2.15\"
";
    assert!(lock_has_package(norway_lock, "serde_norway"));
    assert!(lock_has_package(norway_lock, "unsafe-libyaml-norway"));

    // A saphyr lock passes every check.
    let saphyr_lock = "\
[[package]]
name = \"serde-saphyr\"
version = \"2.0.0\"
dependencies = [
 \"granit-parser\",
]

[[package]]
name = \"granit-parser\"
version = \"0.3.2\"
";
    for pkg in FORBIDDEN_PACKAGES {
        assert!(!lock_has_package(saphyr_lock, pkg), "false hit: {pkg}");
    }
    for pkg in REQUIRED_PACKAGES {
        assert!(lock_has_package(saphyr_lock, pkg), "missed: {pkg}");
    }

    // A lock carrying both generations still flags the forbidden one —
    // coexistence is a regression, not a pass.
    let mixed_lock = format!("{legacy_lock}{saphyr_lock}");
    assert!(lock_has_package(&mixed_lock, "serde_yaml"));
    assert!(lock_has_package(&mixed_lock, "unsafe-libyaml"));
    assert!(lock_has_package(&mixed_lock, "serde-saphyr"));
    assert!(lock_has_package(&mixed_lock, "granit-parser"));

    // A `dependencies` item `"unsafe-libyaml",` is a reference to a
    // package, not a package stanza of its own — and the needle inside
    // `name = "unsafe-libyaml-norway"` must not match either.
    let dep_reference_only = "\
[[package]]
name = \"some-crate\"
version = \"1.0.0\"
dependencies = [
 \"unsafe-libyaml\",
]
";
    assert!(!lock_has_package(dep_reference_only, "unsafe-libyaml"));
    assert!(!lock_has_package(norway_lock, "unsafe-libyaml"));

    // A `[[patch.unused]]` stanza carries the same `name = "PKG"` key
    // shape for a `[patch]` entry cargo resolved as unused. An unused
    // `unsafe-libyaml` patch never enters the dependency graph, so it
    // must not trip the "forbidden backend present" check. The stanza
    // boundary also has to reset cleanly: the `[[package]]` after the
    // patch section is matched again, proving the header tracking
    // re-enters package scope instead of latching off.
    let unused_patch_lock = "\
[[package]]
name = \"serde-saphyr\"
version = \"2.0.0\"

[[patch.unused]]
name = \"unsafe-libyaml\"
version = \"0.2.11\"

[[package]]
name = \"granit-parser\"
version = \"0.3.2\"
";
    assert!(!lock_has_package(unused_patch_lock, "unsafe-libyaml"));
    assert!(lock_has_package(unused_patch_lock, "serde-saphyr"));
    assert!(lock_has_package(unused_patch_lock, "granit-parser"));
}

/// Collect the YAML-backend mentions in one source file that sit inside a
/// public item's declaration, reported as `"{label}:{line}: {text}"`.
///
/// Scanning is a two-state machine over physical lines, because this
/// crate wraps signatures one parameter per line — a `serde_saphyr::`
/// leak is at least as likely to land on a continuation line as on the
/// `pub` line itself, and a same-line check lets it slip. A non-comment
/// line that starts with `pub` — `pub fn`, `pub(crate)`, a `pub struct`
/// field, `pub type`, `pub const`, `pub use`, … — opens a public
/// signature, and every following line stays part of that signature
/// until a line closes it: any line containing `{` (a body or field
/// list opens) or ending with `;` (alias, `use`, or other bare
/// declaration). The closing line is checked *before* it closes, so the
/// single-line `pub fn f() -> serde_saphyr::Options {` flags too.
///
/// Field declarations inside a `pub struct` start with `pub` themselves,
/// so each opens its own record. Comment and doc lines (`//`, `///`,
/// `//!`, `/*`, `*`) are exempt, exactly as the old same-line check
/// exempted them. A flag left set past a `}` errs toward flagging the
/// next item's head — a guard prefers a rare false positive a human
/// clears over a leak it cannot see.
fn yaml_backend_pub_offenders(label: &str, text: &str) -> Vec<String> {
    /// Every YAML backend namespace, current and historical: the guard
    /// must keep all three out of `pub` items so `serde_json::` stays
    /// the only legal value namespace in the API.
    const NEEDLES: &[&str] = &["serde_yaml::", "serde_norway::", "serde_saphyr::"];
    let mut offenders = Vec::new();
    let mut in_pub_signature = false;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }
        if trimmed.starts_with("pub") {
            in_pub_signature = true;
        }
        if in_pub_signature && NEEDLES.iter().any(|n| trimmed.contains(n)) {
            offenders.push(format!("{label}:{}: {trimmed}", index + 1));
        }
        // The line is checked for backend mentions above before `{`/`;`
        // can close the signature, so a single-line signature whose own
        // terminator follows the type still flags.
        if in_pub_signature && (trimmed.contains('{') || trimmed.ends_with(';')) {
            in_pub_signature = false;
        }
    }
    offenders
}

/// The crate's public API must not name the YAML backend's types. Every
/// public value type embedders see is `serde_json::Value`; `serde_saphyr`
/// is only the internal parse/serialise backend
/// (`from_str`/`from_str_with_options`/`to_string_with_options`), so a
/// backend swap is no longer a semver break. Scan `src/*.rs` with
/// [`yaml_backend_pub_offenders`]; internal uses that never sit inside a
/// `pub` item (`parse_raw_yaml`'s local helpers, test-mod bodies, e.g.)
/// are exempt.
#[test]
fn public_api_names_no_yaml_backend_types() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders: Vec<String> = Vec::new();
    for entry in
        fs::read_dir(&src_dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", src_dir.display()))
    {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        offenders.extend(yaml_backend_pub_offenders(
            &path.display().to_string(),
            &text,
        ));
    }
    assert!(
        offenders.is_empty(),
        "public API lines must not name a YAML backend — the exposed value \
         type is serde_json::Value:\n{}",
        offenders.join("\n")
    );
}

/// `yaml_backend_pub_offenders` must follow a `pub` item across the
/// one-parameter-per-line wrapping this crate uses — a backend-type
/// continuation line is the regression shape the guard exists for —
/// without flagging the decoupled `serde_json::` type or non-`pub`
/// internals such as function bodies and `#[cfg(test)]` mods.
#[test]
fn public_signature_scanner_catches_continuation_lines() {
    // Multi-line `pub fn`: the leak lands on a continuation line — each
    // backend namespace flags, current and historical.
    for (name, needle) in [
        ("serde_yaml", "serde_yaml::Value"),
        ("serde_norway", "serde_norway::Value"),
        ("serde_saphyr", "serde_saphyr::Options"),
    ] {
        let multiline = format!(
            "pub fn parse_proxy(\n    raw: &serde_json::Value,\n) -> Result<{needle}> {{\n    unimplemented!()\n}}\n"
        );
        let offenders = yaml_backend_pub_offenders(&format!("{name}.rs"), &multiline);
        assert_eq!(
            offenders.len(),
            1,
            "{name} continuation-line leak missed: {offenders:?}"
        );
        assert!(
            offenders[0].starts_with(&format!("{name}.rs:3:")),
            "{offenders:?}"
        );
    }

    // The closing `{` is checked before it closes the signature, so the
    // single-line form flags too; a `pub` struct field opens a record of
    // its own.
    let single_line = "pub fn f() -> serde_saphyr::Options { unimplemented!() }\n";
    assert_eq!(yaml_backend_pub_offenders("one.rs", single_line).len(), 1);
    let field = "\
pub struct Raw {
    pub payload: serde_saphyr::Options,
}
";
    assert_eq!(yaml_backend_pub_offenders("field.rs", field).len(), 1);

    // The same shape naming the decoupled `serde_json::` type stays
    // clean — and the flag must not bleed into the body, where internal
    // `serde_saphyr::` uses are legitimate.
    let clean = "\
pub fn parse_proxy(
    raw: &serde_json::Value,
) -> Result<serde_json::Value> {
    serde_saphyr::from_str_with_options(raw, opts)
}
";
    assert!(yaml_backend_pub_offenders("clean.rs", clean).is_empty());

    // `serde_saphyr::` inside a `#[cfg(test)]` mod is not public API.
    let test_mod = "\
#[cfg(test)]
mod tests {
    fn parses() {
        let _: serde_json::Value = serde_saphyr::from_str(\"a: b\").unwrap();
    }
}
";
    assert!(yaml_backend_pub_offenders("tests.rs", test_mod).is_empty());
}
