//! Guardrail for the YAML backend (issue #771).
//!
//! `serde_yaml` 0.9.34 links `unsafe-libyaml`, whose repository was archived
//! in 2024 (RUSTSEC-2024-0449). The workspace consumes the maintained
//! `serde_norway` fork under the `serde_yaml` dependency name, so every
//! `serde_yaml::` path in the tree keeps working while the libyaml backend
//! comes from the maintained `unsafe-libyaml-norway` fork.
//!
//! This test pins that arrangement: the archived crate must not be in the
//! dependency graph, and the maintained fork must be. It fails on a tree that
//! still pulls `serde_yaml` 0.9.34.

use std::process::Command;

/// The archived crate, named exactly. `unsafe-libyaml-norway` must not match
/// it, so the check cannot be satisfied by the fork's name.
const ARCHIVED_BACKEND: &str = "unsafe-libyaml";

/// The maintained fork that replaces it.
const MAINTAINED_BACKEND: &str = "unsafe-libyaml-norway";

fn dependency_tree() -> String {
    let output = Command::new("cargo")
        .args(["tree", "-p", "meow-config", "--edges", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree failed");
    assert!(
        output.status.success(),
        "cargo tree failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A package line in `cargo tree` output looks like
/// `unsafe-libyaml v0.2.11` or `unsafe-libyaml-norway v0.2.15`, with tree
/// drawing characters in front. Match the package name as a whole
/// whitespace-separated token so the maintained fork's name does not count
/// as a hit for the archived crate.
fn tree_pulls(tree: &str, package: &str) -> bool {
    tree.lines()
        .any(|line| line.split_whitespace().any(|token| token == package))
}

#[test]
fn yaml_backend_is_the_maintained_fork() {
    let tree = dependency_tree();

    assert!(
        !tree_pulls(&tree, ARCHIVED_BACKEND),
        "meow-config must not pull the archived `{ARCHIVED_BACKEND}` \
         (RUSTSEC-2024-0449); the workspace consumes `serde_norway` instead.\n\
         Dependency tree:\n{tree}"
    );

    assert!(
        tree_pulls(&tree, MAINTAINED_BACKEND),
        "meow-config must pull the maintained `{MAINTAINED_BACKEND}`; the \
         YAML backend was not replaced as expected.\n\
         Dependency tree:\n{tree}"
    );
}
