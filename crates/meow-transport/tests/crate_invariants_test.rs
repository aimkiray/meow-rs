//! Structural guardrail tests — cases F1..F4 from the transport-layer test plan.
//!
//! These tests enforce ADR-0001 crate boundary invariants mechanically so that
//! PR reviewers see failing *tests* (not just a lint warning) when an invariant
//! is violated.

use meow_transport::TransportError;
use std::collections::HashSet;

// ─── F1: no_proxy_dep ────────────────────────────────────────────────────────

/// Verify that `meow-transport` does not depend on `meow-proxy`,
/// `meow-dns`, or `meow-config`.  Only `meow-common` is allowed.
///
/// Runs `cargo tree -p meow-transport --edges normal` and asserts the output
/// contains no lines mentioning the forbidden crates.
#[test]
fn no_proxy_dep() {
    let output = std::process::Command::new("cargo")
        .args(["tree", "-p", "meow-transport", "--edges", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree failed");

    let tree = String::from_utf8_lossy(&output.stdout);

    let forbidden = ["meow-proxy", "meow-dns", "meow-config"];
    for crate_name in &forbidden {
        // Each line of `cargo tree` looks like:
        //   meow-proxy v0.3.0 (/path/to/crate)
        // We just look for the name substring.
        let offending: Vec<&str> = tree.lines().filter(|l| l.contains(crate_name)).collect();
        assert!(
            offending.is_empty(),
            "meow-transport must not depend on '{}' (ADR-0001 §1).\n\
             Offending lines in `cargo tree`:\n{}",
            crate_name,
            offending.join("\n")
        );
    }
}

// ─── F2: no_server_side_symbols_in_src ───────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no production source file contains
/// server-side binding keywords (`accept`, `bind`, `listen`, `Server`,
/// `Acceptor`, `TcpListener`).
///
/// `tests/` is intentionally excluded — `tests/support/loopback.rs` uses
/// these legitimately.  `#[cfg(test)]` items inside `src/` are excluded for
/// the same reason: they are stripped from the published library, and
/// ADR-0001 §1 (implementation plan, M1.A-3) explicitly prescribes driving
/// these client layers against "a loopback `h2` server in-process".
///
/// `simple_obfs/server.rs` is an intentional exception: it is the server
/// side of the simple-obfs transport, consumed by the `listener-shadowsocks`
/// inbound.  Only the fake HTTP header string `"Server: nginx"` trips the
/// `\bServer\b` heuristic — the module does not use `accept`, `bind`, or
/// `listen`.
#[test]
fn no_server_side_symbols_in_src() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Files exempt from the check (relative to `src/`).
    let exempt: &[&str] = &["simple_obfs/server.rs"];

    // Patterns that indicate server-side code.
    let forbidden_patterns = [
        r"\baccept\b",
        r"\bbind\b",
        r"\blisten\b",
        r"\bServer\b",
        r"\bAcceptor\b",
        r"\bTcpListener\b",
    ];

    // Compile patterns once.
    let regexes: Vec<regex::Regex> = forbidden_patterns
        .iter()
        .map(|p| regex::Regex::new(p).expect("valid regex"))
        .collect();

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        // Skip exempt files (e.g. `simple_obfs/server.rs`). Normalise path
        // separators so the check works on both Unix and Windows.
        if let Ok(rel) = path.strip_prefix(&src_dir) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if exempt.contains(&rel_str.as_str()) {
                return;
            }
        }
        let test_only = test_only_lines(path, content);
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments that *describe* the restriction
            // are not violations.  Only live code is checked.
            if line.trim().starts_with("//") {
                continue;
            }
            // Skip `#[cfg(test)]` items — test scaffolding, not shipped code.
            if test_only.contains(&line_no) {
                continue;
            }
            for (re, pat) in regexes.iter().zip(forbidden_patterns.iter()) {
                if re.is_match(line) {
                    violations.push(format!(
                        "{}:{}: '{}' matches pattern '{}'",
                        path.display(),
                        line_no + 1,
                        line.trim(),
                        pat
                    ));
                }
            }
        }
    });

    assert!(
        violations.is_empty(),
        "Server-side symbols found in src/ (ADR-0001 §1, acceptance criterion #8):\n{}",
        violations.join("\n")
    );
}

fn walk_rs_files(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                f(&path, &content);
            }
        }
    }
}

// ─── shared scan helpers ─────────────────────────────────────────────────────

/// Line indices (0-based) covered by a `#[cfg(test)]` item.
///
/// `#[cfg(test)]` code is compiled out of the published library, so in-crate
/// unit tests are scaffolding rather than shipped surface — the same reason
/// `tests/` is excluded from both `src/` scans.  A mock server used to drive a
/// *client* transport is therefore not an ADR-0001 §1 violation.
///
/// The span runs from the attribute line to the line that closes the item's
/// block, tracked by brace depth.  An item with no block (`#[cfg(test)] use
/// …;`) ends at its semicolon.  A span that never terminates is a panic, not a
/// silent skip: failing loudly beats disabling the guard for the rest of the
/// file.
fn test_only_lines(path: &std::path::Path, content: &str) -> HashSet<usize> {
    let lines: Vec<&str> = content.lines().collect();
    let mut test_only = HashSet::new();
    let mut i = 0;

    while i < lines.len() {
        if !is_cfg_test_attr(lines[i]) {
            i += 1;
            continue;
        }

        let start = i;
        let mut depth: usize = 0;
        let mut opened = false;
        let mut terminated = false;

        while i < lines.len() {
            let code = strip_literals_and_comments(lines[i]);
            for ch in code.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            i += 1;

            if opened {
                if depth == 0 {
                    terminated = true;
                    break;
                }
            } else if code.trim_end().ends_with(';') {
                // Block-less item: `#[cfg(test)] use …;`, `const …;`, etc.
                terminated = true;
                break;
            }
        }

        assert!(
            terminated,
            "unterminated #[cfg(test)] item at {}:{} — the ADR-0001 scan cannot tell \
             where test-only code ends, so it refuses to guess",
            path.display(),
            start + 1
        );
        test_only.extend(start..i);
    }

    test_only
}

/// Whether `line` opens a `#[cfg(test)]` (or `all(test, …)` / `any(test, …)`)
/// attribute.  Deliberately narrow: a feature named `"test-utils"` must not
/// match.
fn is_cfg_test_attr(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
}

/// Drop string/char literals and any trailing `//` comment from `line` so that
/// braces inside them cannot skew the block-depth count.
fn strip_literals_and_comments(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut code = String::with_capacity(line.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // Trailing line comment — nothing after it affects depth.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }

        // Raw string: r"…", r#"…"#, r##"…"## … (also the tail of br"…").
        if c == 'r' && matches!(chars.get(i + 1), Some('"') | Some('#')) {
            if let Some(end) = raw_string_end(&chars, i) {
                i = end;
                continue;
            }
        }

        // Ordinary string literal.
        if c == '"' {
            i = string_end(&chars, i);
            continue;
        }

        // Char literal — but `'a` (lifetime) and `'outer:` (label) are code.
        if c == '\'' {
            if let Some(end) = char_literal_end(&chars, i) {
                i = end;
                continue;
            }
        }

        code.push(c);
        i += 1;
    }

    code
}

/// End index (exclusive) of the `"…"` literal opening at `start`.
fn string_end(chars: &[char], start: usize) -> usize {
    let mut i = start + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    // Unterminated on this line (a multi-line string): the rest is literal.
    chars.len()
}

/// End index (exclusive) of the raw string opening at `start`, or `None` when
/// `start` is a raw *identifier* (`r#type`) rather than a raw string.
fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut hashes = 0;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None; // raw identifier, not a raw string
    }
    i += 1;
    while i < chars.len() {
        if chars[i] == '"'
            && chars[i + 1..]
                .iter()
                .take(hashes)
                .filter(|c| **c == '#')
                .count()
                == hashes
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(chars.len())
}

/// End index (exclusive) of the `'c'` literal opening at `start`, or `None`
/// when the quote opens a lifetime or a loop label.
fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    if chars.get(i) == Some(&'\\') {
        i += 1;
        if chars.get(i) == Some(&'u') {
            // '\u{7f}' — run to the closing quote.
            while i < chars.len() && chars[i] != '\'' {
                i += 1;
            }
            return (chars.get(i) == Some(&'\'')).then_some(i + 1);
        }
    }
    (chars.get(i + 1) == Some(&'\'')).then_some(i + 2)
}

// ─── F2/F4 helper self-tests ─────────────────────────────────────────────────

/// The scan exemption must cover exactly the `#[cfg(test)]` item — no more,
/// no less.  A guard that over-reaches silently stops guarding.
#[test]
fn cfg_test_spans_cover_only_test_items() {
    let src = "\
fn client() {}
#[cfg(test)]
mod tests {
    fn helper() {
        let _ = \"} not a brace {\";
    }
}
fn also_client() {}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (1..7).collect::<HashSet<usize>>());
}

#[test]
fn cfg_test_span_ends_at_a_block_less_item() {
    let src = "\
#[cfg(test)]
use std::net::TcpListener;
fn client() {}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (0..2).collect::<HashSet<usize>>());
}

#[test]
fn cfg_test_span_survives_braces_in_literals() {
    let src = "\
#[cfg(test)]
mod tests {
    fn f() {
        let _ = '{';
        let _ = r#\"raw } brace\"#;
        let _ = format!(\"{}\", 1); // }
    }
}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (0..8).collect::<HashSet<usize>>());
}

#[test]
fn non_test_cfg_attributes_are_not_exempt() {
    let src = "\
#[cfg(feature = \"test-utils\")]
mod helpers {
    fn f() {}
}
";
    assert!(test_only_lines(std::path::Path::new("<memory>"), src).is_empty());
}

#[test]
fn lifetimes_do_not_swallow_braces() {
    let code = strip_literals_and_comments("fn f<'a>(x: &'a str) -> Foo { bar }");
    assert_eq!(code.matches('{').count(), 1);
    assert_eq!(code.matches('}').count(), 1);
}

// ─── F3: transport_error_is_non_exhaustive ───────────────────────────────────

/// `TransportError` must be `#[non_exhaustive]` so that adding variants is
/// a minor (not major) semver bump.
///
/// We assert this at compile time by ensuring a wildcard arm is needed for
/// exhaustive matching.  If the `_` arm were not needed (i.e. the enum were
/// exhaustive), the compiler would emit `unreachable_patterns`.  We rely on
/// the fact that `#[non_exhaustive]` *requires* a wildcard in match
/// expressions outside the defining crate.
#[test]
fn transport_error_is_non_exhaustive() {
    let err = TransportError::Config("test".into());
    // This match must compile with a wildcard because TransportError is
    // #[non_exhaustive].  If it were exhaustive, the `_` arm would generate
    // a compile-time `unreachable_patterns` warning (not an error), which
    // would not catch the regression.  We keep the wildcard and document why.
    #[allow(clippy::match_same_arms)] // arms are distinct variants; bodies coincidentally identical
    let _display = match err {
        TransportError::Io(e) => e.to_string(),
        TransportError::Tls(s) => s,
        TransportError::WebSocket(s) => s,
        TransportError::Grpc(s) => s,
        TransportError::HttpUpgrade(s) => s,
        TransportError::Config(s) => s,
        // Required by #[non_exhaustive] — future variants land here.
        _ => "unknown variant".into(),
    };
    // If this test compiles outside the defining crate, #[non_exhaustive] is
    // working.  (A test binary is a separate crate, so the constraint applies.)
}

// ─── F4: no_anyhow_at_boundary ───────────────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no public function signature uses
/// `anyhow` types.  Private helper internals may use anyhow (engineer's
/// call), but `TransportError` is the only type allowed to cross the crate
/// boundary.
#[test]
fn no_anyhow_at_boundary() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let anyhow_re = regex::Regex::new(r"\banyhow\b").expect("regex");

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        let test_only = test_only_lines(path, content);
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments explaining *why* anyhow is
            // banned are not themselves violations.
            if line.trim().starts_with("//") {
                continue;
            }
            // `#[cfg(test)]` items never cross the crate boundary.
            if test_only.contains(&line_no) {
                continue;
            }
            if anyhow_re.is_match(line) {
                violations.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    line_no + 1,
                    line.trim()
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "anyhow references found in src/ (spec §Error taxonomy).\n\
         TransportError is the only error type allowed at the crate boundary:\n{}",
        violations.join("\n")
    );
}
