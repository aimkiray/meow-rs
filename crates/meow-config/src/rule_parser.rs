use std::collections::HashMap;
use std::sync::Arc;

use meow_common::Rule;
use meow_rules::{ParserContext, RuleSet, RuleSetRule};

use crate::sub_rules_parser::{build_sub_rule_rule, parse_sub_rule_reference, SubRuleBlocks};

/// Parse rules with no rule-providers or sub-rule blocks available.
pub fn parse_rules(
    raw_rules: &[String],
    ctx: &ParserContext,
) -> Result<Vec<Box<dyn Rule>>, String> {
    parse_rules_with_providers(raw_rules, &HashMap::new(), ctx)
}

/// Parse the `rules:` block, resolving `RULE-SET,<name>,...` entries against
/// the supplied provider map and delegating everything else to the core
/// `meow_rules::parse_rule`. Sub-rule blocks default to empty.
pub fn parse_rules_with_providers(
    raw_rules: &[String],
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
) -> Result<Vec<Box<dyn Rule>>, String> {
    parse_rules_full(raw_rules, providers, ctx, &HashMap::new())
}

/// Parse the `rules:` block with full resolver context — providers, ctx,
/// and pre-resolved sub-rule blocks for `SUB-RULE,<name>` entries.
///
/// A single unparseable line fails the whole block: upstream mihomo drops it
/// with a warning and keeps routing the rest, which turns a typo into a
/// silent hole in the policy — traffic the operator wrote a rule for now
/// falls through to whatever comes next, usually `MATCH,DIRECT` (issue #513).
pub fn parse_rules_full(
    raw_rules: &[String],
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    sub_rules: &SubRuleBlocks,
) -> Result<Vec<Box<dyn Rule>>, String> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    for line in raw_rules {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_one_rule_or_subrule(line, providers, ctx, sub_rules) {
            Ok(rule) => rules.push(rule),
            Err(e) => return Err(format!("rules: cannot parse '{line}': {e}")),
        }
    }
    Ok(rules)
}

/// Parse a single rule line. Handles `RULE-SET,<name>,...`,
/// `SUB-RULE,<name>`, and delegates everything else to the core
/// `meow_rules::parse_rule`.
pub fn parse_one_rule_or_subrule(
    line: &str,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
    sub_rules: &SubRuleBlocks,
) -> Result<Box<dyn Rule>, String> {
    if let Some(result) = try_parse_rule_set(line, providers) {
        return result;
    }
    if let Some(block_name) = parse_sub_rule_reference(line) {
        return build_sub_rule_rule(&block_name, sub_rules);
    }
    meow_rules::parse_rule(line, ctx)
}

/// Returns `Some(...)` only when `line` is a RULE-SET entry; `None` means
/// "not a RULE-SET, keep going down the parser chain".
fn try_parse_rule_set(
    line: &str,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
) -> Option<Result<Box<dyn Rule>, String>> {
    let parts: Vec<&str> = line.splitn(4, ',').map(str::trim).collect();
    if parts.first().copied() != Some("RULE-SET") {
        return None;
    }
    if parts.len() < 3 {
        return Some(Err("RULE-SET needs <name>,<adapter>".into()));
    }
    let name = parts[1];
    let adapter = parts[2];
    let no_resolve = parts
        .get(3)
        .is_some_and(|extra| extra.eq_ignore_ascii_case("no-resolve"));

    let Some(set) = providers.get(name) else {
        return Some(Err(format!("unknown rule-provider '{name}'")));
    };

    Some(Ok(Box::new(RuleSetRule::new(
        name,
        Arc::clone(set),
        adapter,
        no_resolve,
    ))))
}
