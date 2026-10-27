//! A single-pass, span-carrying, document-order-preserving YAML tree plus
//! the hand-written [`serde::Deserializer`] that walks it into
//! [`crate::raw::RawConfig`].
//!
//! Why this exists (PR #827, ADR-0007): routing `RawConfig` straight
//! through serde-saphyr's streaming deserializer monomorphizes its
//! sizeable parser state machines across every `Raw*` type, which alone
//! pushed the `aarch64-musl` `minimal` binary past the 8 MiB budget. An
//! intermediate `serde_json::Value` pass fixed the size but cost document
//! order (a second saphyr overlay pass had to re-read `hosts` /
//! `nameserver-policy`), source locations on type errors, the scalar-text
//! coercions saphyr applies (`port: "7890"`, `secret: 123456`), and let a
//! top-level *sequence* fill `RawConfig` positionally.
//!
//! This module keeps the size win differently: saphyr parses the document
//! **once** into [`SpannedNode`] — a small typed tree that keeps each
//! node's source location and every mapping's document order — and the
//! compact [`NodeDe`] deserializer below produces `RawConfig` with the
//! same scalar-coercion contract the direct saphyr path had. All
//! YAML-layer invariants (`<<:` merge expansion appended at the map tail,
//! duplicate-key rejection, `!tag` refusal, `strict_booleans`, the depth
//! budget, anchor resolution) are enforced by saphyr's event stream before
//! a node ever reaches the tree, so none of them is re-implemented here.

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

/// One YAML node with its scalar's resolved type and, for containers, the
/// document order retained.
///
/// `Int` is `i128`: saphyr's `deserialize_any` reports plain YAML ints via
/// `visit_i64`/`visit_u64` (both fit `i128`), and anything wider already
/// arrives as `Float` — saphyr falls back to `f64` for u64-overflowing
/// literals. `Float` may be non-finite: `NonFiniteFloatPolicy::PassThrough`
/// in `yaml_options` makes the *typeless* resolution (`deserialize_any`,
/// via `try_parse_float_incl_overflow`) hand `.inf`/`-.inf`/`.nan` and
/// `f64`-overflowing literals (`1e999`) through as IEEE values — matching
/// what the direct path delivered to `serde_json::Value` targets (which
/// flatten them to `null`) and to any other typeless consumer. A typed
/// `f64` field on the direct path was stricter: `parse_yaml12_float`
/// rejects `1e999` behind its `is_finite` filter while still accepting
/// the named `.inf`/`.nan` spellings — both arrive here as the same
/// non-finite `Float` node, so `NodeDe::deserialize_f64` cannot tell an
/// overflow literal from a named one. That residual widening is latent
/// only: no `Raw*` field is `f64`/`f32`-typed today.
/// `'de` is the input-document lifetime: saphyr hands plain, unescaped
/// scalars back as borrows of the source text, so `Str` is a `Cow` — most
/// strings in the tree are zero-copy views into the document, only
/// escaped/quoted scalars own their bytes.
#[derive(Debug)]
pub(crate) enum YamlNode<'de> {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(Cow<'de, str>),
    Seq(Vec<SpannedNode<'de>>),
    /// Key order = document order; `<<:` merge entries were already
    /// expanded into this sequence by saphyr's map machinery. Keys carry
    /// their own span and tag (a `SpannedNode` like values): key-side
    /// errors — `~` keys, container keys, `!!`-tagged scalar keys that
    /// can't feed a string — point at the key's own position rather than
    /// borrowing the value's.
    Map(Vec<(SpannedNode<'de>, SpannedNode<'de>)>),
}

impl YamlNode<'_> {
    /// The scalar's text in the form the typed field parsers below
    /// consume — on the direct path saphyr's `deserialize_u16` /
    /// `deserialize_bool` / `deserialize_f64` all parsed the scalar's raw
    /// text, so they re-parse this canonical form identically
    /// (`parse_int_unsigned("0x1F")` and `parse_int_unsigned("31")`
    /// produce the same `31`).
    ///
    /// Strings report verbatim. Resolved scalars report a canonical form:
    /// ints as decimal digits (`0x1F` arrives as `31`, `+7890` as `7890`),
    /// bools as `true`/`false` (a case-folded `TrUe` arrives as `true`),
    /// non-finite floats as `.nan`/`.inf`/`-.inf`, other floats via
    /// `f64`'s shortest `Display` (`0123`, resolved to `123.0`, reports as
    /// `123`). String targets do not read this form for an untagged
    /// resolved scalar: they get its source spelling (see
    /// [`string_text`]), as the direct saphyr path and mihomo deliver it —
    /// `password: 000000` stays `000000`. The canonical form is only the
    /// fallback when the node's position yields no plausible spelling.
    ///
    /// `Null` reports `"null"` for the numeric/bool paths (failing their
    /// parses exactly like a literal `~`/`null` did) but is special-cased
    /// where saphyr gave null its own verdicts: `Option` → `None`, `String`
    /// → `cannot deserialize null into string`, `char` → its null error,
    /// `unit`/map/seq → empty.
    fn scalar_text(&self) -> Option<Cow<'_, str>> {
        match self {
            YamlNode::Str(s) => Some(Cow::Borrowed(s.as_ref())),
            YamlNode::Int(v) => Some(Cow::Owned(v.to_string())),
            YamlNode::Bool(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
            YamlNode::Float(v) => Some(Cow::Owned(float_text(*v))),
            YamlNode::Null => Some(Cow::Borrowed("null")),
            YamlNode::Seq(_) | YamlNode::Map(_) => None,
        }
    }
}

/// `f64` text for the scalar-coercion path, in the YAML spellings saphyr
/// produced for the non-finite literals.
fn float_text(v: f64) -> String {
    if v.is_nan() {
        ".nan".to_string()
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            "-.inf"
        } else {
            ".inf"
        }
        .to_string()
    } else {
        v.to_string()
    }
}

impl<'de> serde::Deserialize<'de> for YamlNode<'de> {
    /// The tree is driven by `deserialize_any` so saphyr's own resolver
    /// decides each scalar's type (null → bool → int → float → string,
    /// honoring `strict_booleans` and explicit core tags) and each
    /// container's shape; `SpannedNode` children re-enter through the
    /// `__yaml_spanned` newtype hook and carry their use/definition
    /// locations with them.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NodeVisitor;

        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = YamlNode<'de>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any YAML node")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(YamlNode::Null)
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(YamlNode::Null)
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(YamlNode::Bool(v))
            }

            fn visit_i8<E: de::Error>(self, v: i8) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_i16<E: de::Error>(self, v: i16) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_i32<E: de::Error>(self, v: i32) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(v))
            }

            fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_u16<E: de::Error>(self, v: u16) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_u32<E: de::Error>(self, v: u32) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(YamlNode::Int(i128::from(v)))
            }
            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
                // Unreachable through saphyr's `deserialize_any` (it only
                // emits i64/u64/f64) — degrade to float like saphyr's own
                // oversized-int fallback.
                Ok(i128::try_from(v)
                    .map(YamlNode::Int)
                    .unwrap_or(YamlNode::Float(v as f64)))
            }

            fn visit_f32<E: de::Error>(self, v: f32) -> Result<Self::Value, E> {
                Ok(YamlNode::Float(f64::from(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(YamlNode::Float(v))
            }

            fn visit_char<E: de::Error>(self, v: char) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Owned(v.to_string())))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Owned(v.to_string())))
            }
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Borrowed(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Owned(v)))
            }
            // Defensive: under `ignore_binary_tag_for_string` saphyr delivers
            // a `!!binary` scalar as its base64 *text* (a `visit_str`), never
            // bytes — these arms exist only so the visitor stays total if a
            // different deserializer ever drives `YamlNode`.
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Owned(
                    String::from_utf8_lossy(v).into_owned(),
                )))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(YamlNode::Str(Cow::Owned(
                    String::from_utf8_lossy(&v).into_owned(),
                )))
            }

            fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                <YamlNode<'de> as serde::Deserialize>::deserialize(deserializer)
            }

            fn visit_newtype_struct<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                <YamlNode<'de> as serde::Deserialize>::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element::<SpannedNode<'de>>()? {
                    items.push(item);
                }
                Ok(YamlNode::Seq(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(key) = map.next_key::<SpannedNode<'de>>()? {
                    let value = map.next_value::<SpannedNode<'de>>()?;
                    entries.push((key, value));
                }
                Ok(YamlNode::Map(entries))
            }
        }

        deserializer.deserialize_any(NodeVisitor)
    }
}

/// A 1-indexed source position. Owns just the `line`/`column` pair a
/// diagnostic renders — the `span`/`source_id` members saphyr's
/// `Location` also carries are skipped during capture (below) since no
/// consumer reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Loc {
    pub line: u64,
    pub column: u64,
}

impl Loc {
    /// `Location::UNKNOWN` parity — 0/0, meaning "no position captured".
    const UNKNOWN: Self = Self { line: 0, column: 0 };
}

/// The parsed document and its line starts. String targets slice an
/// untagged resolved scalar's source spelling out of it, at the node's
/// `defined` position (see [`string_text`]) — line and column, which the
/// tree already reads, so no saphyr span type is driven.
pub(crate) struct Source<'de> {
    doc: &'de str,
    /// Byte offset of each line's first byte. A line ends at `\n`, `\r\n`
    /// or a lone `\r` — YAML's three line breaks — so the index agrees
    /// with saphyr's line numbers; a leading BOM is not part of the first
    /// line, as saphyr's columns don't count it.
    line_starts: Vec<usize>,
}

impl<'de> Source<'de> {
    pub(crate) fn new(doc: &'de str) -> Self {
        let bytes = doc.as_bytes();
        let mut line_starts = vec![if doc.starts_with('\u{feff}') { 3 } else { 0 }];
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' || (b == b'\r' && bytes.get(i + 1) != Some(&b'\n')) {
                line_starts.push(i + 1);
            }
        }
        Self { doc, line_starts }
    }

    /// The plain scalar starting at `loc` (1-indexed line, column counted
    /// in chars): it runs to the first blank, flow indicator, `#` or `:`,
    /// none of which a scalar resolved to a number or bool contains, and
    /// never past its line.
    fn plain_scalar_at(&self, loc: Loc) -> Option<&'de str> {
        let line = usize::try_from(loc.line).ok()?.checked_sub(1)?;
        let column = usize::try_from(loc.column).ok()?.checked_sub(1)?;
        let start = *self.line_starts.get(line)?;
        let end = self
            .line_starts
            .get(line + 1)
            .copied()
            .unwrap_or(self.doc.len());
        let rest = &self.doc[start..end];
        let rest = &rest[rest.char_indices().nth(column)?.0..];
        let end = rest
            .find(|c: char| {
                c.is_whitespace() || matches!(c, ',' | '[' | ']' | '{' | '}' | '#' | ':')
            })
            .unwrap_or(rest.len());
        Some(&rest[..end]).filter(|s| !s.is_empty())
    }
}

/// The explicit tag a node carried, bucketed to saphyr's reachable
/// `SfTag` set. Saphyr resolves a scalar's tag into the node type itself
/// (`!!int 42` lands as `Int(42)`), which hid the direct path's tag
/// checks: its typed deserializers still ran `validate_core_scalar_tag`
/// (`port: !!str 7890` → `invalid u16`) and `can_parse_into_string`
/// (`secret: !!int 42` → `cannot deserialize tagged scalar into string`)
/// on the *event's* tag. Capturing the tag beside the node lets
/// [`NodeDe`]/[`KeyDe`] re-enforce both.
///
/// The set is limited by `reject_unsupported_tags` in `yaml_options`:
/// anything outside the core schema, `!!timestamp`, `!!binary`,
/// `!!merge`/`!!value` or the non-specific `!`/`!!` marks already failed
/// the parse before a node exists — those sit in `Permissive` for
/// completeness but are unreachable in practice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeTag {
    Str,
    Int,
    Float,
    Bool,
    Null,
    Seq,
    Map,
    Timestamp,
    Binary,
    /// `!` / `!!` — forces string resolution but skips the core-tag
    /// checks (it is not a core-schema tag).
    NonSpecific,
    /// `!!merge`/`!!value` key marks and anything else saphyr let
    /// through: non-core and string-compatible — behaves like untagged.
    Permissive,
}

impl NodeTag {
    /// `SfTag::is_core` parity — the YAML 1.2 core-schema tags.
    const fn is_core(self) -> bool {
        matches!(
            self,
            NodeTag::Str
                | NodeTag::Int
                | NodeTag::Float
                | NodeTag::Bool
                | NodeTag::Null
                | NodeTag::Seq
                | NodeTag::Map
        )
    }

    /// `SfTag::can_parse_into_string` parity, minus `Binary` (our
    /// `ignore_binary_tag_for_string` option admits it): the tags whose
    /// scalars the direct path refused to feed a `str`/`String` target.
    /// `Seq`/`Map` are listed for completeness — they can only sit on
    /// containers, which fail `expected string scalar` earlier.
    const fn barred_from_string(self) -> bool {
        matches!(
            self,
            NodeTag::Int
                | NodeTag::Float
                | NodeTag::Bool
                | NodeTag::Null
                | NodeTag::Seq
                | NodeTag::Map
                | NodeTag::Timestamp
        )
    }

    /// Bucket a resolved tag URI/local name as `__yaml_tagged` reports it
    /// (`Tag`'s `Display` — `!!int` arrives resolved to
    /// `tag:yaml.org,2002:int`, `!int` stays local). The
    /// `tag:yaml.org,2002:!x` spellings are verbatim forms saphyr's
    /// lookup table also maps.
    fn from_raw(raw: &str) -> Self {
        match raw {
            "!" | "!!" => NodeTag::NonSpecific,
            "!str" | "tag:yaml.org,2002:str" | "tag:yaml.org,2002:!str" => NodeTag::Str,
            "!int" | "tag:yaml.org,2002:int" | "tag:yaml.org,2002:!int" => NodeTag::Int,
            "!float" | "tag:yaml.org,2002:float" | "tag:yaml.org,2002:!float" => NodeTag::Float,
            "!bool" | "tag:yaml.org,2002:bool" | "tag:yaml.org,2002:!bool" => NodeTag::Bool,
            "!null" | "tag:yaml.org,2002:null" | "tag:yaml.org,2002:!null" => NodeTag::Null,
            "!seq" | "tag:yaml.org,2002:seq" | "tag:yaml.org,2002:!seq" => NodeTag::Seq,
            "!map" | "tag:yaml.org,2002:map" | "tag:yaml.org,2002:!map" => NodeTag::Map,
            "!timestamp"
            | "tag:yaml.org,2002:timestamp"
            | "tag:yaml.org,2002:!timestamp"
            | "!time"
            | "tag:yaml.org,2002:time"
            | "tag:yaml.org,2002:!time" => NodeTag::Timestamp,
            "!binary" | "tag:yaml.org,2002:binary" | "tag:yaml.org,2002:!binary" => NodeTag::Binary,
            _ => NodeTag::Permissive,
        }
    }
}

/// A [`YamlNode`] paired with the locations saphyr exposes through its
/// `__yaml_spanned` newtype hook — the same data `serde_saphyr::Spanned`
/// yields, but captured with a lean drive of the synthesized map instead
/// of `Spanned`'s generic `Deserialize`: fixed-order zero-alloc field
/// checks, only `line`/`column` read out of each `Location` (early return
/// skips `span`/`source_id`), and no per-node `String` field buffer.
///
/// The `tag` member comes from a second hook: `SpannedNode` requests the
/// `__yaml_tagged` newtype first (the same protocol
/// `serde_saphyr::Tagged` uses — a virtual `[value, tag?]` sequence whose
/// element 0 is the node and element 1 the resolved tag string), and its
/// element-0 seed runs the `__yaml_spanned` drive.
///
/// Relies on serde-saphyr 2.x internals — the `"__yaml_tagged"` /
/// `"__yaml_spanned"` newtype names, the `[value, tag?]` element order,
/// and the fixed `[marker, value, referenced, defined]` /
/// `[line, column, span, source_id]` field orders. Every step is checked
/// against the expected name, so a protocol change fails loudly here
/// rather than mislabeling locations or tags. The workspace pins
/// `serde-saphyr = "=2.0.0"` for exactly this reason.
#[derive(Debug)]
pub(crate) struct SpannedNode<'de> {
    pub node: YamlNode<'de>,
    /// Use-site (`referenced`) location — for an alias/merge-expanded
    /// node the `*`/`<<:` position. Diagnostics point here.
    pub loc: Loc,
    /// Definition-site (`defined`) location — for an alias the anchored
    /// node's, where its source spelling is (see [`string_text`]).
    pub defined: Loc,
    /// The node's explicit tag, [`None`] when untagged (nearly all).
    /// See [`NodeTag`] for why it is kept.
    pub tag: Option<NodeTag>,
}

/// Map-key seed checking the synthesized `Spanned`/`Location` field
/// names — zero-alloc `&str` compare that errors loudly if saphyr ever
/// changes the protocol instead of silently reading the wrong field.
struct KeyCheck(&'static str);

impl<'de> DeserializeSeed<'de> for KeyCheck {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CheckVisitor(&'static str);

        impl<'de> Visitor<'de> for CheckVisitor {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "the synthesized field name `{}`", self.0)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v == self.0 {
                    Ok(())
                } else {
                    Err(E::custom(format!("unexpected __yaml_spanned field `{v}`")))
                }
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                CheckVisitor(self.0).visit_str(&v)
            }
        }

        deserializer.deserialize_identifier(CheckVisitor(self.0))
    }
}

/// Read the next synthesized-map key and require it to be `expected`.
fn check_key<'de, A>(map: &mut A, expected: &'static str) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    match map.next_key_seed(KeyCheck(expected))? {
        Some(()) => Ok(()),
        None => Err(de::Error::custom("truncated __yaml_spanned map")),
    }
}

/// `line`/`column` capture for a synthesized `Location` — declared as a
/// struct target (the only shape `LocationDeser` answers) and stops after
/// the two fields used, never materializing `span`/`source_id`.
impl<'de> serde::Deserialize<'de> for Loc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LineColVisitor;

        impl<'de> Visitor<'de> for LineColVisitor {
            type Value = Loc;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a saphyr Location")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                check_key::<A>(&mut map, "line")?;
                let line = map.next_value::<u64>()?;
                check_key::<A>(&mut map, "column")?;
                let column = map.next_value::<u64>()?;
                Ok(Loc { line, column })
            }
        }

        deserializer.deserialize_struct("Location", &["line", "column"], LineColVisitor)
    }
}

/// The `__yaml_spanned` half of a [`SpannedNode`] — `(node, loc)` without
/// the tag. Kept as its own seed so the tagged drive below can pull it as
/// sequence element 0.
struct SpannedCore<'de> {
    node: YamlNode<'de>,
    loc: Loc,
    defined: Loc,
}

impl<'de> serde::Deserialize<'de> for SpannedCore<'de> {
    /// `Spanned<T>` reaches the location-capture hook by naming the
    /// `__yaml_spanned` newtype; this does the same, then drives the
    /// synthesized `{marker, value, referenced, defined}` map directly.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SpannedVisitor;

        impl<'de> Visitor<'de> for SpannedVisitor {
            type Value = SpannedCore<'de>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a saphyr __yaml_spanned node")
            }

            fn visit_newtype_struct<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(SpannedFields)
            }
        }

        struct SpannedFields;

        impl<'de> Visitor<'de> for SpannedFields {
            type Value = SpannedCore<'de>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("saphyr's synthesized Spanned map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                // `__serde_saphyr_private_spanned: true` marker — the name
                // saphyr also uses to detect this map on buffered paths.
                check_key::<A>(&mut map, "__serde_saphyr_private_spanned")?;
                map.next_value::<de::IgnoredAny>()?;
                check_key::<A>(&mut map, "value")?;
                let node = map.next_value::<YamlNode<'de>>()?;
                check_key::<A>(&mut map, "referenced")?;
                let loc = map.next_value::<Loc>()?;
                check_key::<A>(&mut map, "defined")?;
                let defined = map.next_value::<Loc>()?;
                Ok(SpannedCore { node, loc, defined })
            }
        }

        deserializer.deserialize_newtype_struct("__yaml_spanned", SpannedVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for SpannedNode<'de> {
    /// Requests the `__yaml_tagged` newtype — saphyr answers with a
    /// virtual sequence whose element 0 is the node (driven as
    /// [`SpannedCore`], which in turn names `__yaml_spanned`) and whose
    /// element 1 is the resolved tag string, present only for explicitly
    /// tagged nodes. Works at every position the tree is driven —
    /// document root, map values, *and* map keys — because each goes
    /// through the same `deserialize_newtype_struct` dispatch.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TaggedVisitor;

        impl<'de> Visitor<'de> for TaggedVisitor {
            type Value = SpannedNode<'de>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a saphyr __yaml_tagged node")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let Some(core) = seq.next_element::<SpannedCore<'de>>()? else {
                    return Err(de::Error::custom("truncated __yaml_tagged seq"));
                };
                // Element 1 exists only when the node carried a tag and is
                // delivered through serde's `StringDeserializer` — a plain
                // `String` seed (an `Option` seed would ask it for
                // `deserialize_option`, which a value deserializer can't
                // answer).
                let tag = seq
                    .next_element::<String>()?
                    .as_deref()
                    .map(NodeTag::from_raw);
                Ok(SpannedNode {
                    node: core.node,
                    loc: core.loc,
                    defined: core.defined,
                    tag,
                })
            }

            /// Transparent fallback for a deserializer that does not know
            /// `__yaml_tagged` (the tree is only ever built by
            /// `from_str_with_options`, but a plain `IgnoredAny`-style
            /// drive must still terminate): treat the node as untagged.
            fn visit_newtype_struct<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                let core = <SpannedCore as serde::Deserialize>::deserialize(deserializer)?;
                Ok(SpannedNode {
                    node: core.node,
                    loc: core.loc,
                    defined: core.defined,
                    tag: None,
                })
            }
        }

        deserializer.deserialize_newtype_struct("__yaml_tagged", TaggedVisitor)
    }
}

/// Deserialization error carrying the leaf node's source location plus the
/// dotted field path accumulated as the error bubbles out through nested
/// map values and sequence elements.
///
/// `Display` renders `line {l} column {c}: {path}: {msg}` — the same
/// information the direct path's `serde_saphyr::Error` showed for these
/// failures (`{msg} at line {l}, column {c}` plus a source snippet), so
/// `-t` and `PUT /configs` output keeps line/column navigation. The
/// snippet itself is not reproduced.
#[derive(Debug)]
pub(crate) struct TreeError {
    /// Location of the innermost failing node; the first deserializer
    /// frame the error escapes through fills it.
    location: Option<Loc>,
    /// Field-path segments, outermost first; `[i]` entries fuse onto the
    /// preceding segment when rendered (`proxies[0].port`).
    path: Vec<String>,
    msg: String,
}

impl TreeError {
    fn new(location: Loc, msg: impl Into<String>) -> Self {
        Self {
            location: (location != Loc::UNKNOWN).then_some(location),
            path: Vec::new(),
            msg: msg.into(),
        }
    }

    /// Attach `location` unless a deeper frame already set one — the
    /// innermost (leaf) span wins.
    fn at(mut self, location: Loc) -> Self {
        if self.location.is_none() && location != Loc::UNKNOWN {
            self.location = Some(location);
        }
        self
    }

    /// Prepend one path segment (`fallback-filter`, `[0]`).
    fn prepend(mut self, segment: String) -> Self {
        self.path.insert(0, segment);
        self
    }

    fn path_string(&self) -> String {
        let mut out = String::new();
        for seg in &self.path {
            if seg.starts_with('[') {
                out.push_str(seg);
            } else {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(seg);
            }
        }
        out
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(loc) = self.location {
            write!(f, "line {} column {}: ", loc.line, loc.column)?;
        }
        let path = self.path_string();
        if !path.is_empty() {
            write!(f, "{path}: ")?;
        }
        f.write_str(&self.msg)
    }
}

impl std::error::Error for TreeError {}

impl de::Error for TreeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self {
            location: None,
            path: Vec::new(),
            msg: msg.to_string(),
        }
    }
}

// ── scalar coercions, replicating serde-saphyr's typed-scalar parsers ────
//
// On the direct path saphyr's `deserialize_u16`/`deserialize_bool`/
// `deserialize_f64`/`deserialize_char` all received the scalar's *text*
// and ran `parse_int_signed`/`parse_int_unsigned`/`parse_yaml12_float`/
// the strict-boolean check over it. `yaml_options` leaves
// `legacy_octal_numbers` and `angle_conversions` at their defaults (off),
// under which those parsers reduce to the replicas below — quoted scalars
// reach them because saphyr's typed methods always parsed the text.

/// `yaml_trim` parity — scalar conversion trims ASCII padding (spaces,
/// tabs, and line breaks that quoted/block scalars may carry).
fn yaml_trim(s: &str) -> &str {
    s.trim_matches([' ', '\t', '\r', '\n'])
}

/// `parse_digits_u128` parity: digits plus `_` separators that may only
/// sit between two digits.
fn parse_digits_u128(digits: &str, radix: u32) -> Option<u128> {
    let mut val: u128 = 0;
    let mut saw = false;
    let bytes = digits.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'_' => {
                let ok =
                    i > 0 && bytes[i - 1] != b'_' && i + 1 < bytes.len() && bytes[i + 1] != b'_';
                if !ok {
                    return None;
                }
            }
            b'0'..=b'9' => {
                let d = u32::from(b - b'0');
                if d >= radix {
                    return None;
                }
                val = val.checked_mul(u128::from(radix))?;
                val = val.checked_add(u128::from(d))?;
                saw = true;
            }
            b'a'..=b'f' if radix > 10 => {
                let d = 10 + u32::from(b - b'a');
                if d >= radix {
                    return None;
                }
                val = val.checked_mul(u128::from(radix))?;
                val = val.checked_add(u128::from(d))?;
                saw = true;
            }
            b'A'..=b'F' if radix > 10 => {
                let d = 10 + u32::from(b - b'A');
                if d >= radix {
                    return None;
                }
                val = val.checked_mul(u128::from(radix))?;
                val = val.checked_add(u128::from(d))?;
                saw = true;
            }
            _ => return None,
        }
    }
    saw.then_some(val)
}

/// `radix_and_digits` parity with `legacy_octal_numbers` unset: `0x`/`0X`
/// hex, `0o`/`0O` octal, `0b`/`0B` binary, else decimal.
fn radix_and_digits(rest: &str) -> (u32, &str) {
    if let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (16, r)
    } else if let Some(r) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
        (8, r)
    } else if let Some(r) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
        (2, r)
    } else {
        (10, rest)
    }
}

/// `parse_int_signed` parity: `+`/`-` sign, radix prefixes, the YAML 1.2
/// leading-zero decimal rejection, then a range check into `T`.
fn parse_int_signed<T: TryFrom<i128>>(s: &str) -> Option<T> {
    let t = yaml_trim(s);
    let (neg, rest) = match t.strip_prefix('+') {
        Some(r) => (false, r),
        None => match t.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, t),
        },
    };
    let (radix, digits) = radix_and_digits(rest);
    if radix == 10 && digits.starts_with('0') && digits != "0" {
        return None;
    }
    let mag = parse_digits_u128(digits, radix)?;
    let val: i128 = if neg {
        if mag == (i128::MAX as u128) + 1 {
            i128::MIN
        } else {
            i128::try_from(mag).ok()?.checked_neg()?
        }
    } else {
        i128::try_from(mag).ok()?
    };
    T::try_from(val).ok()
}

/// `parse_int_unsigned` parity: `-` rejected, `+` allowed.
fn parse_int_unsigned<T: TryFrom<u128>>(s: &str) -> Option<T> {
    let t = yaml_trim(s);
    if t.starts_with('-') {
        return None;
    }
    let rest = t.strip_prefix('+').unwrap_or(t);
    let (radix, digits) = radix_and_digits(rest);
    if radix == 10 && digits.starts_with('0') && digits != "0" {
        return None;
    }
    let mag = parse_digits_u128(digits, radix)?;
    T::try_from(mag).ok()
}

/// `parse_yaml12_float` parity with `angle_conversions` unset: `.nan` /
/// `±.inf` spellings map to non-finite values; anything else must be a
/// *finite* `f64` parse — the `is_finite` filter also rejects Rust-only
/// `inf`/`infinity`/`nan` spellings and `f64`-overflowing literals
/// (`1e999`) exactly like saphyr's `parse_yaml12_finite_float_fallback`.
fn parse_f64(s: &str) -> Option<f64> {
    let t = yaml_trim(s);
    match t.to_ascii_lowercase().as_str() {
        ".nan" | "+.nan" | "-.nan" => Some(f64::NAN),
        ".inf" | "+.inf" => Some(f64::INFINITY),
        "-.inf" => Some(f64::NEG_INFINITY),
        _ => t.parse::<f64>().ok().filter(|v| v.is_finite()),
    }
}

/// The strict-boolean check saphyr runs under `strict_booleans` — only the
/// `true`/`false` spellings, ASCII case-insensitive.
fn parse_strict_bool(s: &str) -> Option<bool> {
    let t = yaml_trim(s);
    if t.eq_ignore_ascii_case("true") {
        Some(true)
    } else if t.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// The location a node's errors carry: the use-site (`referenced`)
/// location — for aliases and merge-derived values the `*`/`<<:` site.
fn node_loc(node: &SpannedNode<'_>) -> Loc {
    node.loc
}

/// The text a `str`/`String` target (a field or a map key) receives for a
/// non-null scalar. An untagged resolved scalar delivers its source
/// spelling — `0123`, `000000`, `0x1F`, `+7`, `TrUe`, `1e999` arrive
/// verbatim, as on the direct saphyr path and in mihomo, instead of the
/// canonical `123`/`0`/`31`/`7`/`true`/`.inf` that would silently rewrite
/// a password, secret or filter regex. Strings are already verbatim, and
/// a tagged scalar (`!!int 42`) keeps its tag verdicts, so both use
/// [`YamlNode::scalar_text`], as does a node whose position yields no
/// plausible spelling.
fn string_text<'de>(node: &'de SpannedNode<'de>, source: &Source<'de>) -> Option<Cow<'de, str>> {
    if node.tag.is_none() {
        // A first char the resolved kind can't start with means the
        // position is off; keep the canonical text rather than a wrong
        // slice.
        let plausible: fn(char) -> bool = match node.node {
            YamlNode::Int(_) | YamlNode::Float(_) => {
                |c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.')
            }
            YamlNode::Bool(_) => |c| matches!(c, 't' | 'T' | 'f' | 'F'),
            _ => return node.node.scalar_text(),
        };
        if let Some(raw) = source
            .plain_scalar_at(node.defined)
            .filter(|raw| raw.starts_with(plausible))
        {
            return Some(Cow::Borrowed(raw));
        }
    }
    node.node.scalar_text()
}

/// The field-path segment a map key renders as — the key's
/// [`string_text`], as the map received it.
fn key_segment<'de>(key: &'de SpannedNode<'de>, source: &Source<'de>) -> String {
    match string_text(key, source) {
        Some(text) => text.into_owned(),
        None => node_kind(&key.node).to_string(),
    }
}

/// A sequence element's escaping error. A visitor-raised error (an
/// untagged enum, a custom `Deserialize`) has no location yet: it belongs
/// to this element, not to whatever enclosing node would attach its own
/// on the way out. Out of line so the per-type accessor instantiations
/// stay small.
#[cold]
#[inline(never)]
fn element_error(e: TreeError, node: &SpannedNode<'_>, idx: usize) -> TreeError {
    e.at(node_loc(node)).prepend(format!("[{idx}]"))
}

/// A map value's escaping error — see [`element_error`].
#[cold]
#[inline(never)]
fn entry_error<'de>(
    e: TreeError,
    key: &'de SpannedNode<'de>,
    value: &SpannedNode<'_>,
    source: &Source<'de>,
) -> TreeError {
    e.at(node_loc(value)).prepend(key_segment(key, source))
}

/// The node's kind word for "expected string scalar"-style fallbacks.
fn node_kind(node: &YamlNode<'_>) -> &'static str {
    match node {
        YamlNode::Null => "null",
        YamlNode::Bool(_) => "boolean",
        YamlNode::Int(_) => "integer",
        YamlNode::Float(_) => "floating point",
        YamlNode::Str(_) => "string",
        YamlNode::Seq(_) => "sequence",
        YamlNode::Map(_) => "mapping",
    }
}

// ── the tree deserializer ────────────────────────────────────────────────

/// A `serde::Deserializer` over one [`YamlNode`]/[`Loc`] pair.
///
/// Semantics mirror the direct serde-saphyr path point by point:
///
/// - scalar→string delivers the scalar's source spelling (`secret: 123456`
///   → `"123456"`, `password: 000000` → `"000000"`, see [`string_text`]),
///   and quoted strings parse into numeric/bool targets
///   (`port: "7890"` → `7890`, `ipv6: "true"` → `true`) — both exactly as
///   saphyr's text-driven typed methods behaved;
/// - `Null` is `None` for `Option`, an empty map for map/struct targets,
///   an empty seq for seq targets, `()` for unit — and a hard error for
///   `String`/`char`, matching saphyr's null verdicts;
/// - non-finite floats stay `Float` nodes, so `Option<u16>: .inf` errors
///   instead of collapsing to `None`; they flatten to `null` only inside
///   `serde_json::Value` targets, whose own visitor does that;
/// - map iteration is document order, so `IndexMap` targets (`hosts`,
///   `nameserver-policy`) preserve it for free while `serde_json::Value`
///   targets still sort into their `BTreeMap`;
/// - explicit-tag checks the tree's `deserialize_any` resolution hid are
///   re-enforced from the captured tag: a scalar carrying a mismatched
///   core-schema tag fails `invalid {ty}` (`port: !!str 7890`), and a
///   scalar tagged `!!int`/`!!float`/`!!bool`/`!!timestamp` never reaches
///   a string target (`secret: !!int 42`);
/// - every error carries the node's `line/column` plus the field path
///   (`dns.fallback-filter.geoip`, `proxies[0].port`) accumulated by the
///   enclosing map/seq accesses — key-side errors use the key's own
///   position, which `SpannedNode` keys now carry;
/// - a non-mapping top node — including the previously accepted top-level
///   *sequence* — errors `expected mapping start`, closing the positional
///   struct-fill hole.
///
/// Residual differences from the direct path, by construction:
///
/// - a negative-zero literal (`-0`, `-0x0`, …) resolves to `Int(0)` —
///   the minus sign is gone before the tree sees the scalar — so an
///   unsigned field accepts it where `parse_int_unsigned` rejected
///   `-`-prefixed text. Reachable (`port: -0` → `0`) but meaningless;
///   disclosed in CHANGELOG rather than narrowed.
/// - `1e999`-style `f64`-overflowing literals land on the same
///   non-finite `Float` node the named `.inf`/`.nan` spellings produce,
///   so a *typed* `f64` field could not keep rejecting the overflow
///   forms the way `parse_yaml12_float`'s `is_finite` filter did —
///   latent only: no `Raw*` field is `f64`/`f32`-typed today.
/// - `!!timestamp` scalars fail at tree build (their canonical form is
///   not string-shaped), which *narrows* the one direct-path case that
///   tolerated them (`port: !!timestamp 7890` parsed the text into the
///   `u16`).
#[derive(Clone, Copy)]
struct NodeDe<'de> {
    sn: &'de SpannedNode<'de>,
    source: &'de Source<'de>,
}

impl<'de> NodeDe<'de> {
    fn node(&self) -> &'de YamlNode<'de> {
        &self.sn.node
    }

    fn tag(&self) -> Option<NodeTag> {
        self.sn.tag
    }

    fn loc(&self) -> Loc {
        node_loc(self.sn)
    }

    fn err(&self, msg: impl Into<String>) -> TreeError {
        TreeError::new(self.loc(), msg)
    }

    fn scalar_text(&self) -> Option<Cow<'de, str>> {
        self.node().scalar_text()
    }

    /// `invalid {ty}` — saphyr's `InvalidScalar` message — at this node.
    fn invalid_scalar(&self, ty: &'static str) -> TreeError {
        self.err(format!("invalid {ty}"))
    }

    /// Containers where a scalar was expected: saphyr's
    /// `take_scalar_cow_event` verdict, `expected string scalar`.
    fn expect_scalar(&self) -> TreeError {
        self.err("expected string scalar")
    }

    /// saphyr `validate_core_scalar_tag` parity — an explicit core-schema
    /// tag that disagrees with the typed request fails `invalid {ty}`
    /// before the text parse (`port: !!str 7890` was rejected on the
    /// direct path). Non-core tags (`!!binary`, `!!timestamp`, `!`) skip
    /// the check there, so they skip it here.
    fn check_core_tag(&self, expected: NodeTag, ty: &'static str) -> Result<(), TreeError> {
        match self.tag() {
            Some(t) if t.is_core() && t != expected => Err(self.invalid_scalar(ty)),
            _ => Ok(()),
        }
    }

    /// saphyr `can_parse_into_string` parity for `str`/`String` targets —
    /// a scalar whose explicit tag marks a non-string type (`!!int`,
    /// `!!float`, `!!bool`, `!!timestamp`) failed the string request on
    /// the direct path even though its canonical text would coerce
    /// (`secret: !!int 42`, `mode: !!bool true`). `!!binary` is admitted
    /// by `ignore_binary_tag_for_string`, and `Null`-tagged scalars
    /// already resolve to `YamlNode::Null`, which has its own verdict.
    fn check_stringable(&self) -> Result<(), TreeError> {
        match self.tag() {
            Some(t) if t.barred_from_string() => {
                Err(self.err("cannot deserialize tagged scalar into string"))
            }
            _ => Ok(()),
        }
    }

    /// Unsigned-integer field value. `Int` range-checks (a negative `Int`
    /// fails exactly like a `-`-prefixed text did); `Str` parses its text
    /// (`port: "7890"`); `Float` fails outright — its source spelling
    /// always carried a `.`/`e`/`.nan`/`.inf` that the int parser rejects,
    /// and the canonical text (`1500` for `1500.0`) would lie; `Bool`/
    /// `Null` texts fail the parse the same way they did on the direct
    /// path.
    fn uint<T: TryFrom<u128>>(&self, ty: &'static str) -> Result<T, TreeError> {
        match self.node() {
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                self.check_core_tag(NodeTag::Int, ty)?;
                match self.node() {
                    YamlNode::Int(v) => u128::try_from(*v)
                        .ok()
                        .and_then(|m| T::try_from(m).ok())
                        .ok_or_else(|| self.invalid_scalar(ty)),
                    YamlNode::Float(_) => Err(self.invalid_scalar(ty)),
                    _ => parse_int_unsigned::<T>(&self.scalar_text().unwrap_or_default())
                        .ok_or_else(|| self.invalid_scalar(ty)),
                }
            }
        }
    }

    /// Signed-integer field value; same rules as [`NodeDe::uint`].
    fn sint<T: TryFrom<i128>>(&self, ty: &'static str) -> Result<T, TreeError> {
        match self.node() {
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                self.check_core_tag(NodeTag::Int, ty)?;
                match self.node() {
                    YamlNode::Int(v) => T::try_from(*v).map_err(|_| self.invalid_scalar(ty)),
                    YamlNode::Float(_) => Err(self.invalid_scalar(ty)),
                    _ => parse_int_signed::<T>(&self.scalar_text().unwrap_or_default())
                        .ok_or_else(|| self.invalid_scalar(ty)),
                }
            }
        }
    }

    /// No `Raw*` field is tuple/tuple-struct/array-typed today, but serde
    /// routes `[T; N]` and tuples through `deserialize_tuple`, so the
    /// declared length must still be enforced — saphyr's own
    /// `deserialize_tuple` wraps the sequence in a `TupleLenVisitor` that
    /// errors `invalid length` on any trailing element. Checking the
    /// materialized length up front rejects both directions (a shorter
    /// sequence would otherwise surface only as serde's own
    /// `invalid_length` after the fact). A non-`Seq` node defers to the
    /// normal `deserialize_seq` verdicts (`expected sequence start`, or
    /// the empty-sequence treatment for `Null`).
    fn check_tuple_len(&self, len: usize, what: &'static str) -> Result<(), TreeError> {
        if let YamlNode::Seq(items) = self.node() {
            if items.len() != len {
                return Err(self.err(format!(
                    "invalid length {}, expected a {what} of length {len}",
                    items.len()
                )));
            }
        }
        Ok(())
    }
}

macro_rules! deser_uint {
    ($method:ident, $ty:ty, $visit:ident) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            let v: $ty = self.uint(stringify!($ty))?;
            visitor.$visit(v).map_err(|e: TreeError| e.at(self.loc()))
        }
    };
}

macro_rules! deser_sint {
    ($method:ident, $ty:ty, $visit:ident) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            let v: $ty = self.sint(stringify!($ty))?;
            visitor.$visit(v).map_err(|e: TreeError| e.at(self.loc()))
        }
    };
}

/// Shared scalar→string delivery: verbatim for `Str`, the source spelling
/// for the resolved scalars (see [`string_text`]).
fn visit_strlike<'de, V: Visitor<'de>>(
    de: &NodeDe<'de>,
    visitor: V,
) -> Result<V::Value, TreeError> {
    match de.node() {
        YamlNode::Null => Err(de.err("cannot deserialize null into string; use Option<String>")),
        YamlNode::Seq(_) | YamlNode::Map(_) => Err(de.expect_scalar()),
        _ => {
            de.check_stringable()?;
            // Borrowed for `Str` and for a sliced source spelling; owned
            // only for the canonical fallback.
            match string_text(de.sn, de.source).expect("scalars have scalar text") {
                Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
                Cow::Owned(s) => visitor.visit_string(s),
            }
            .map_err(|e: TreeError| e.at(de.loc()))
        }
    }
}

impl<'de> de::Deserializer<'de> for NodeDe<'de> {
    type Error = TreeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match self.node() {
            YamlNode::Null => visitor.visit_unit(),
            YamlNode::Bool(b) => visitor.visit_bool(*b),
            YamlNode::Int(v) => {
                if *v < 0 {
                    match i64::try_from(*v) {
                        Ok(v) => visitor.visit_i64(v),
                        Err(_) => visitor.visit_i128(*v),
                    }
                } else {
                    match u64::try_from(*v) {
                        Ok(v) => visitor.visit_u64(v),
                        Err(_) => visitor.visit_i128(*v),
                    }
                }
            }
            YamlNode::Float(v) => visitor.visit_f64(*v),
            YamlNode::Str(s) => visitor.visit_borrowed_str(s.as_ref()),
            YamlNode::Seq(_) => self.deserialize_seq(visitor),
            YamlNode::Map(_) => self.deserialize_map(visitor),
        }
        .map_err(|e: TreeError| e.at(loc))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                self.check_core_tag(NodeTag::Bool, "boolean")?;
                let text = self.scalar_text().unwrap_or_default();
                let b = parse_strict_bool(&text)
                    .ok_or_else(|| self.err("invalid boolean (strict mode expects true/false)"))?;
                visitor
                    .visit_bool(b)
                    .map_err(|e: TreeError| e.at(self.loc()))
            }
        }
    }

    deser_sint!(deserialize_i8, i8, visit_i8);
    deser_sint!(deserialize_i16, i16, visit_i16);
    deser_sint!(deserialize_i32, i32, visit_i32);
    deser_sint!(deserialize_i64, i64, visit_i64);
    deser_sint!(deserialize_i128, i128, visit_i128);
    deser_uint!(deserialize_u8, u8, visit_u8);
    deser_uint!(deserialize_u16, u16, visit_u16);
    deser_uint!(deserialize_u32, u32, visit_u32);
    deser_uint!(deserialize_u64, u64, visit_u64);
    deser_uint!(deserialize_u128, u128, visit_u128);

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_f64(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                self.check_core_tag(NodeTag::Float, "floating point")?;
                match self.node() {
                    YamlNode::Float(v) => visitor
                        .visit_f64(*v)
                        .map_err(|e: TreeError| e.at(self.loc())),
                    YamlNode::Int(v) => visitor
                        .visit_f64(*v as f64)
                        .map_err(|e: TreeError| e.at(self.loc())),
                    _ => {
                        let text = self.scalar_text().unwrap_or_default();
                        let v = parse_f64(&text)
                            .ok_or_else(|| self.invalid_scalar("floating point"))?;
                        visitor
                            .visit_f64(v)
                            .map_err(|e: TreeError| e.at(self.loc()))
                    }
                }
            }
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => {
                Err(self.err("invalid char: cannot deserialize null; use Option<char>"))
            }
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                let text = self.scalar_text().unwrap_or_default();
                let mut it = text.chars();
                match (it.next(), it.next()) {
                    (Some(c), None) => visitor
                        .visit_char(c)
                        .map_err(|e: TreeError| e.at(self.loc())),
                    _ => Err(self.err("invalid char: expected a single Unicode scalar value")),
                }
            }
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visit_strlike(&self, visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visit_strlike(&self, visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            // A u8-element sequence, as saphyr accepted for byte targets.
            YamlNode::Seq(_) => self.deserialize_seq(visitor),
            YamlNode::Map(_) => Err(self.err("expected scalar (!!binary) or sequence of 0..=255")),
            // No `Raw*` field is byte-typed, so the walk does not carry a
            // base64 decoder for the `!!binary` scalars the direct path
            // decoded (a narrowing only reachable by a future field).
            YamlNode::Str(_) if self.tag() == Some(NodeTag::Binary) => {
                Err(self.err("bytes not supported (!!binary decode not implemented)"))
            }
            _ => Err(self.err("bytes not supported (missing !!binary tag)")),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
        .map_err(|e: TreeError| e.at(self.loc()))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => visitor
                .visit_unit()
                .map_err(|e: TreeError| e.at(self.loc())),
            _ => Err(self.err("unexpected value for unit")),
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => visitor
                .visit_unit()
                .map_err(|e: TreeError| e.at(self.loc())),
            // saphyr accepted an empty mapping as a unit struct.
            YamlNode::Map(entries) if entries.is_empty() => visitor
                .visit_unit()
                .map_err(|e: TreeError| e.at(self.loc())),
            YamlNode::Map(_) => Err(self.err("expected empty mapping for unit struct")),
            _ => Err(self.err("unexpected value for unit")),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match self.node() {
            YamlNode::Seq(items) => visitor
                .visit_seq(NodeSeqAcc {
                    iter: items.iter(),
                    idx: 0,
                    source: self.source,
                })
                .map_err(|e: TreeError| e.at(loc)),
            // saphyr treated a null-like scalar as an empty sequence.
            YamlNode::Null => visitor
                .visit_seq(NodeSeqAcc {
                    iter: [].iter(),
                    idx: 0,
                    source: self.source,
                })
                .map_err(|e: TreeError| e.at(loc)),
            _ => Err(self.err("expected sequence start")),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.check_tuple_len(len, "tuple")?;
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.check_tuple_len(len, "tuple struct")?;
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match self.node() {
            YamlNode::Map(entries) => visitor
                .visit_map(NodeMapAcc {
                    iter: entries.iter(),
                    pending: None,
                    seen: HashSet::new(),
                    source: self.source,
                })
                .map_err(|e: TreeError| e.at(loc)),
            // saphyr treated a null-like scalar as an empty mapping — this
            // is what normalizes an empty/`null` document into the
            // all-defaults `RawConfig`.
            YamlNode::Null => visitor
                .visit_map(NodeMapAcc {
                    iter: [].iter(),
                    pending: None,
                    seen: HashSet::new(),
                    source: self.source,
                })
                .map_err(|e: TreeError| e.at(loc)),
            _ => Err(self.err("expected mapping start")),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Seq(_) => Err(self.err("externally tagged enum expected scalar or mapping")),
            YamlNode::Map(entries) => match entries.as_slice() {
                [(key, value)] => visitor
                    .visit_enum(TreeEnumAccess {
                        variant: KeyDe {
                            sn: key,
                            source: self.source,
                        },
                        value: Some(value),
                    })
                    .map_err(|e: TreeError| e.at(self.loc())),
                [] => Err(self.err("unexpected mapping end")),
                _ => Err(self.err("expected end of mapping after enum variant value")),
            },
            // A scalar names a unit variant (`mode: rule`-style); the
            // scalar's text is the variant name, as saphyr's EnumScalarId
            // delivered it.
            _ => visitor
                .visit_enum(TreeEnumAccess {
                    variant: KeyDe {
                        sn: self.sn,
                        source: self.source,
                    },
                    value: None,
                })
                .map_err(|e: TreeError| e.at(self.loc())),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        // The node is already materialized — ignoring it is a no-op.
        visitor
            .visit_unit()
            .map_err(|e: TreeError| e.at(self.loc()))
    }

    fn is_human_readable(&self) -> bool {
        true
    }
}

/// `SeqAccess` over a `YamlNode::Seq`, in document order. Index path
/// segments (`[3]`) are fused onto the parent key when an element's error
/// bubbles out.
struct NodeSeqAcc<'de> {
    iter: std::slice::Iter<'de, SpannedNode<'de>>,
    idx: usize,
    source: &'de Source<'de>,
}

impl<'de> SeqAccess<'de> for NodeSeqAcc<'de> {
    type Error = TreeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        let Some(node) = self.iter.next() else {
            return Ok(None);
        };
        let idx = self.idx;
        self.idx += 1;
        // A visitor-raised error (an untagged enum, a custom `Deserialize`)
        // has no location yet: it belongs to this element, not to
        // whatever enclosing node would attach its own on the way out.
        seed.deserialize(NodeDe {
            sn: node,
            source: self.source,
        })
        .map(Some)
        .map_err(|e| element_error(e, node, idx))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

/// `MapAccess` over a `YamlNode::Map`, in document order. The key's scalar
/// text becomes the path segment prepended to a value's escaping error —
/// rendered lazily so the no-error path allocates nothing per key.
///
/// `seen` tracks the text every key already yielded was delivered as (its
/// [`string_text`]): saphyr's key-fingerprint dedup runs on *resolved*
/// scalars, so it lets `{1: a, "1": b}` or `{0x1F: a, "0x1F": b}` through
/// as two distinct keys (an int beside a string), yet both read as the
/// one key `"1"`/`"0x1F"` in the `IndexMap<String, _>`/`BTreeMap`/
/// `String`-keyed maps every `RawConfig` map type becomes, where a silent
/// `insert` would drop the first entry. The document is rejected instead
/// — a config whose maps genuinely contain such twin keys is a config bug,
/// and erroring preserves the map-shape invariant every downstream
/// consumer assumes. Distinct spellings of one value (`{TrUe: a, "true":
/// b}`, `{1.0: a, "1": b}`) are distinct strings and stay two keys, as on
/// the direct path.
struct NodeMapAcc<'de> {
    iter: std::slice::Iter<'de, (SpannedNode<'de>, SpannedNode<'de>)>,
    /// `(value node, key node)` of the in-flight entry.
    pending: Option<(&'de SpannedNode<'de>, &'de SpannedNode<'de>)>,
    /// Delivered texts of keys already yielded — see the type docs. Only
    /// scalar keys are tracked (container keys fail `expected string
    /// scalar` at `KeyDe`); `HashSet::new` allocates nothing until the
    /// first insert.
    seen: HashSet<Cow<'de, str>>,
    source: &'de Source<'de>,
}

impl<'de> MapAccess<'de> for NodeMapAcc<'de> {
    type Error = TreeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        let Some((key, value)) = self.iter.next() else {
            return Ok(None);
        };
        if let Some(text) = string_text(key, self.source) {
            if !self.seen.insert(text.clone()) {
                return Err(TreeError::new(
                    node_loc(key),
                    format!(
                        "duplicate mapping key `{text}` — distinct YAML scalars read as the same string"
                    ),
                ));
            }
        }
        self.pending = Some((value, key));
        seed.deserialize(KeyDe {
            sn: key,
            source: self.source,
        })
        .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let Some((value, key)) = self.pending.take() else {
            // Unreachable under the `MapAccess` contract (serde visitors
            // only request a value after a key was yielded) — the guard
            // stays so a hand-rolled visitor gets an error instead of a
            // panic.
            return Err(de::Error::custom("value requested before key"));
        };
        // As in `NodeSeqAcc`: a location-less error is this value's.
        seed.deserialize(NodeDe {
            sn: value,
            source: self.source,
        })
        .map_err(|e| entry_error(e, key, value, self.source))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

/// A map *key* deserializer. Keys are scalars: a resolved scalar reports
/// its source spelling (`123`, `0x1F`, `TrUe`, `1.50`, `.inf` keys all
/// work and arrive verbatim), as the direct path delivered it into
/// `String` keys — see [`string_text`]. A `~`/empty key fails the
/// string-shaped requests, an explicit non-string tag (`{!!int 42: x}`)
/// fails the same `can_parse_into_string` check the direct path ran on
/// keys, and a container key is `expected string scalar`.
#[derive(Clone, Copy)]
struct KeyDe<'de> {
    /// The key node — its own location (`__yaml_spanned` delivers one for
    /// keys just like values) and its explicit tag, which gets the same
    /// checks as a value's: a `!!int`-tagged scalar key never fed a
    /// `String` map on the direct path.
    sn: &'de SpannedNode<'de>,
    source: &'de Source<'de>,
}

impl<'de> KeyDe<'de> {
    fn loc(&self) -> Loc {
        node_loc(self.sn)
    }

    fn node(&self) -> &'de YamlNode<'de> {
        &self.sn.node
    }

    fn tag(&self) -> Option<NodeTag> {
        self.sn.tag
    }

    fn err(&self, msg: impl Into<String>) -> TreeError {
        TreeError::new(self.loc(), msg)
    }

    /// The key's text for string-shaped requests — its [`string_text`].
    fn text(&self) -> Result<Cow<'de, str>, TreeError> {
        self.check_stringable()?;
        string_text(self.sn, self.source).ok_or_else(|| self.err("expected string scalar"))
    }

    /// Null and container keys, and keys tagged with a non-string type,
    /// fail the string-shaped requests.
    fn check_stringable(&self) -> Result<(), TreeError> {
        match self.node() {
            YamlNode::Null => {
                Err(self.err("cannot deserialize null into string; use Option<String>"))
            }
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.err("expected string scalar")),
            _ if self.tag().is_some_and(NodeTag::barred_from_string) => {
                Err(self.err("cannot deserialize tagged scalar into string"))
            }
            _ => Ok(()),
        }
    }
}

impl<'de> de::Deserializer<'de> for KeyDe<'de> {
    type Error = TreeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        // Typeless key positions (serde's `Content` buffer inside untagged
        // enums) got the *typed* key value on the direct path — saphyr's
        // `deserialize_any` infers `123`→int even in key position — so
        // dispatch by node kind exactly like `NodeDe::deserialize_any`.
        NodeDe {
            sn: self.sn,
            source: self.source,
        }
        .deserialize_any(visitor)
    }

    /// Struct-field/enum-variant names: saphyr routed identifier requests
    /// through `deserialize_str`, so a key reports its scalar text rather
    /// than a typed visit (which serde's field visitor would reject as an
    /// index it doesn't have).
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match self.text()? {
            Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
            Cow::Owned(s) => visitor.visit_string(s),
        }
        .map_err(|e: TreeError| e.at(loc))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        visitor
            .visit_string(self.text()?.into_owned())
            .map_err(|e: TreeError| e.at(loc))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
        .map_err(|e: TreeError| e.at(self.loc()))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.node() {
            YamlNode::Null => visitor
                .visit_unit()
                .map_err(|e: TreeError| e.at(self.loc())),
            _ => Err(self.err("unexpected value for unit")),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        if let Some(t) = self.tag() {
            if t.is_core() && t != NodeTag::Bool {
                // `validate_core_scalar_tag` parity for bool-key targets —
                // `!!str true` as a key rejected `invalid boolean`.
                return Err(self.err("invalid boolean"));
            }
        }
        // The resolved form, as before: a `TrUe` key spells `true`.
        self.check_stringable()?;
        let text = self.node().scalar_text().unwrap_or_default();
        let b = parse_strict_bool(&text)
            .ok_or_else(|| self.err("invalid boolean (strict mode expects true/false)"))?;
        visitor.visit_bool(b).map_err(|e: TreeError| e.at(loc))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    serde::forward_to_deserialize_any! {
        i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char
        bytes byte_buf unit_struct seq tuple tuple_struct map struct enum
        ignored_any
    }
}

/// `EnumAccess`/`VariantAccess` for the externally-tagged form — `Variant`
/// scalar or `{Variant: value}` single-key map. (`RawConfig` only carries
/// untagged/unit enums, which serde drives through `deserialize_any` and
/// the unit-variant path instead; this exists so the trait surface is
/// complete for any future enum.)
struct TreeEnumAccess<'de> {
    variant: KeyDe<'de>,
    value: Option<&'de SpannedNode<'de>>,
}

impl<'de> EnumAccess<'de> for TreeEnumAccess<'de> {
    type Error = TreeError;
    type Variant = TreeVariantAccess<'de>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let (value, source) = (self.value, self.variant.source);
        seed.deserialize(self.variant)
            .map(|variant| (variant, TreeVariantAccess { value, source }))
    }
}

struct TreeVariantAccess<'de> {
    value: Option<&'de SpannedNode<'de>>,
    source: &'de Source<'de>,
}

impl<'de> TreeVariantAccess<'de> {
    fn require_value(&self) -> Result<NodeDe<'de>, TreeError> {
        match self.value {
            Some(node) => Ok(NodeDe {
                sn: node,
                source: self.source,
            }),
            None => Err(de::Error::custom("expected a variant value")),
        }
    }
}

impl<'de> VariantAccess<'de> for TreeVariantAccess<'de> {
    type Error = TreeError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        match self.value {
            // A bare scalar (`Variant`) or `{Variant: ~}` carries no payload.
            None => Ok(()),
            Some(node) if matches!(node.node, YamlNode::Null) => Ok(()),
            Some(node) => Err(TreeError::new(
                node_loc(node),
                "unexpected value for unit enum variant",
            )),
        }
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        seed.deserialize(self.require_value()?)
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        de::Deserializer::deserialize_tuple(self.require_value()?, len, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        de::Deserializer::deserialize_map(self.require_value()?, visitor)
    }
}

/// Walk a materialized [`SpannedNode`] document into [`RawConfig`]
/// through [`NodeDe`]. [`crate::parse_raw_yaml`] performs the saphyr
/// parse itself — `yaml_options` (merge expansion, duplicate-key errors,
/// tag rejection, strict booleans, non-finite passthrough, depth budget)
/// applies there, before any node reaches this walk. Kept signature-clean
/// of backend paths so the `yaml_backend_test` public-API guard holds:
/// the body names `serde_saphyr` types, declarations only `SpannedNode`.
///
/// `doc` must be the text `root` was parsed from: string targets slice
/// their source spellings out of it.
pub(crate) fn deserialize_config<'de>(
    root: &'de SpannedNode<'de>,
    doc: &'de str,
) -> Result<crate::raw::RawConfig, TreeError> {
    let source = Source::new(doc);
    <crate::raw::RawConfig as serde::Deserialize>::deserialize(NodeDe {
        sn: root,
        source: &source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SpannedNode` is the tree root saphyr fills: every node
    /// carries its location, maps keep document order, scalars resolve.
    #[test]
    fn tree_keeps_spans_and_order() {
        let doc = "b: 1\na:\n  z: [true, 2.5, x]\n  y: ~\n";
        let root: SpannedNode<'_> =
            serde_saphyr::from_str_with_options(doc, crate::yaml_options()).unwrap();
        assert_eq!(root.loc.line, 1);
        let YamlNode::Map(entries) = &root.node else {
            panic!("expected a map, got {:?}", root.node);
        };
        let keys: Vec<Option<Cow<'_, str>>> =
            entries.iter().map(|(k, _)| k.node.scalar_text()).collect();
        assert_eq!(keys, [Some(Cow::Borrowed("b")), Some(Cow::Borrowed("a"))]);

        let YamlNode::Int(one) = entries[0].1.node else {
            panic!("expected int");
        };
        assert_eq!(one, 1);
        let YamlNode::Map(inner) = &entries[1].1.node else {
            panic!("expected inner map");
        };
        let YamlNode::Seq(items) = &inner[0].1.node else {
            panic!("expected seq");
        };
        assert!(matches!(items[0].node, YamlNode::Bool(true)));
        assert!(matches!(items[1].node, YamlNode::Float(v) if v == 2.5));
        assert!(matches!(&items[2].node, YamlNode::Str(s) if s.as_ref() == "x"));
        assert_eq!(items[2].loc.line, 3);
        assert!(matches!(inner[1].1.node, YamlNode::Null));
    }

    /// Keys carry their own `loc`/`tag` — an explicit `!!str` key keeps
    /// its position, which `KeyDe` reports on error instead of borrowing
    /// the value's.
    #[test]
    fn tree_keeps_key_spans_and_tags() {
        let doc = "!!int 42: a\nb: 1\n";
        let root: SpannedNode<'_> =
            serde_saphyr::from_str_with_options(doc, crate::yaml_options()).unwrap();
        let YamlNode::Map(entries) = &root.node else {
            panic!("expected a map, got {:?}", root.node);
        };
        assert!(matches!(entries[0].0.node, YamlNode::Int(42)));
        assert_eq!(entries[0].0.tag, Some(NodeTag::Int));
        // The span anchors at the scalar (`42`), just after `!!int `.
        assert_eq!((entries[0].0.loc.line, entries[0].0.loc.column), (1, 7));
        assert!(matches!(&entries[1].0.node, YamlNode::Str(s) if s.as_ref() == "b"));
        assert_eq!(entries[1].0.tag, None);
    }

    #[test]
    fn scalar_text_canonical_forms() {
        let doc: SpannedNode<'_> = serde_saphyr::from_str_with_options(
            "[0x1F, +7, TrUe, .nan, -.inf, 1.5]",
            crate::yaml_options(),
        )
        .unwrap();
        let YamlNode::Seq(items) = &doc.node else {
            panic!("expected seq");
        };
        let texts: Vec<String> = items
            .iter()
            .map(|n| n.node.scalar_text().unwrap().into_owned())
            .collect();
        assert_eq!(texts, ["31", "7", "true", ".nan", "-.inf", "1.5"]);
    }

    /// A helper deserializing a one-field map's single value into the
    /// given owned Rust type — the smallest drive through `NodeDe` that
    /// exercises the typed-scalar paths.
    fn parse_field<T: serde::de::DeserializeOwned>(doc: &str) -> Result<T, TreeError> {
        let root: SpannedNode<'_> =
            serde_saphyr::from_str_with_options(doc, crate::yaml_options()).unwrap();
        let YamlNode::Map(entries) = &root.node else {
            panic!("expected a map, got {:?}", root.node);
        };
        let (_key, value) = &entries[0];
        let source = Source::new(doc);
        T::deserialize(NodeDe {
            sn: value,
            source: &source,
        })
    }

    /// Deserialize a whole document as a `String`-keyed map.
    fn parse_map<T: serde::de::DeserializeOwned>(
        doc: &str,
    ) -> Result<indexmap::IndexMap<String, T>, TreeError> {
        let root: SpannedNode<'_> =
            serde_saphyr::from_str_with_options(doc, crate::yaml_options()).unwrap();
        let source = Source::new(doc);
        serde::Deserialize::deserialize(NodeDe {
            sn: &root,
            source: &source,
        })
    }

    /// An untagged resolved scalar reaches a `String` target as its
    /// source spelling, not its canonical text: a password `000000` must
    /// not become `0`, nor a regex `01` become `1`.
    #[test]
    fn string_targets_get_source_spelling() {
        for spelling in [
            "000000",
            "0123",
            "0x1F",
            "+7",
            "TrUe",
            "1.50",
            "1e999",
            "123e4567",
            ".inf",
            "99999999999999999999",
            "123456789012345678901234567890",
        ] {
            assert_eq!(
                parse_field::<String>(&format!("secret: {spelling}  # comment\n")).unwrap(),
                spelling
            );
        }
        // Flow sequences, aliases (the anchor's text, not `*x`), merge
        // keys, multi-byte text before the scalar, a BOM and CRLF line ends.
        assert_eq!(
            parse_field::<Vec<String>>("x: [01, 0x1F ,+7]").unwrap(),
            ["01", "0x1F", "+7"]
        );
        let map = parse_map::<String>("a: &x 000\nb: *x\n").unwrap();
        assert_eq!((map["a"].as_str(), map["b"].as_str()), ("000", "000"));
        let map =
            parse_map::<indexmap::IndexMap<String, String>>("base: &b {k: 0123}\nm:\n  <<: *b\n")
                .unwrap();
        assert_eq!(map["m"]["k"], "0123");
        let map = parse_map::<String>("\u{5bc6}\u{7801}: 00042\n").unwrap();
        assert_eq!(map["\u{5bc6}\u{7801}"], "00042");
        let map = parse_map::<String>("\u{feff}secret: 0123\n").unwrap();
        assert_eq!(map["secret"], "0123");
        let map = parse_map::<String>("a: x\r\nsecret: 0123\r\nb:\t007\r\n").unwrap();
        assert_eq!((map["secret"].as_str(), map["b"].as_str()), ("0123", "007"));
        // Columns count chars, astral ones included; a lone `\r` ends a line.
        let map = parse_map::<Vec<String>>("k: [\u{20000}, 0x0A]\n").unwrap();
        assert_eq!(map["k"], ["\u{20000}", "0x0A"]);
        let map = parse_map::<String>("a: x\rsecret: 0123\rb: 007\r").unwrap();
        assert_eq!((map["secret"].as_str(), map["b"].as_str()), ("0123", "007"));
        // Keys too, and the typed paths still read the resolved value.
        let map = parse_map::<u16>("{0x1F: 0x1F, TrUe: 10, 1.50: +7}").unwrap();
        let entries: Vec<(&str, u16)> = map.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(entries, [("0x1F", 31), ("TrUe", 10), ("1.50", 7)]);
        // A tagged scalar keeps its verdict instead of its spelling.
        assert!(parse_field::<String>("secret: !!float 1.50").is_err());
        assert_eq!(parse_field::<String>("secret: !!str 0123").unwrap(), "0123");
    }

    /// A visitor-raised error (here: no `HostsValue`-style untagged
    /// variant matches) carries the failing value's position, not the
    /// enclosing key's or element's.
    #[test]
    fn visitor_errors_use_the_value_location() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(untagged)]
        #[allow(dead_code)]
        enum One {
            Text(String),
            Number(u16),
        }
        let err = parse_map::<One>("a.example: [1, 2]\n").unwrap_err();
        assert!(err.to_string().starts_with("line 1 column 12"), "{err}");
        let err = parse_field::<Vec<One>>("x:\n  - ok\n  - {k: v}\n").unwrap_err();
        assert!(err.to_string().starts_with("line 3 column 5"), "{err}");
    }

    /// `{1: a, "1": b}` / `{0x1F: a, "0x1F": b}` survive saphyr's
    /// resolved-scalar fingerprint dedup as distinct keys, but the
    /// `IndexMap<String, _>` a `hosts:`/`nameserver-policy:` map becomes
    /// would silently drop the first entry — the delivered-text dedup in
    /// `NodeMapAcc` must reject the document instead.
    #[test]
    fn same_string_key_collision_rejected() {
        for doc in ["{1: a, \"1\": b}", "{0x1F: a, \"0x1F\": b}"] {
            let err = parse_map::<String>(doc).expect_err(&format!("{doc} should fail"));
            assert!(
                err.to_string().contains("duplicate mapping key"),
                "{doc} -> {err}"
            );
        }
    }

    /// Distinct spellings are distinct strings, even when they resolve to
    /// one value: `{TrUe: a, "true": b}` keeps both keys, as the direct
    /// path did.
    #[test]
    fn distinct_spellings_stay_distinct_keys() {
        for (doc, keys) in [
            ("{TrUe: a, \"true\": b}", ["TrUe", "true"]),
            ("{1.0: a, \"1\": b}", ["1.0", "1"]),
            ("{1: a, 1.5: b}", ["1", "1.5"]),
        ] {
            let map = parse_map::<String>(doc).unwrap();
            assert_eq!(map.keys().map(String::as_str).collect::<Vec<_>>(), keys);
        }
    }

    /// Explicit-tag coercion parity with the direct path: a scalar
    /// carrying a *different* core-schema tag fails `invalid {ty}`, and
    /// an `!!int`/`!!float`/`!!bool` scalar never feeds a `String`.
    #[test]
    fn explicit_tag_checks_match_direct_path() {
        // Value side: mismatched core tag → `invalid u16`/`invalid boolean`.
        assert!(parse_field::<u16>("port: !!str 7890").is_err());
        assert!(parse_field::<u16>("port: !!float 7890").is_err());
        assert!(parse_field::<bool>("ipv6: !!str true").is_err());
        assert!(parse_field::<bool>("ipv6: !!int 1").is_err());
        // String targets reject non-string core tags outright.
        for doc in [
            "secret: !!int 42",
            "secret: !!float 4.2",
            "secret: !!bool true",
        ] {
            let err = parse_field::<String>(doc).expect_err(doc);
            assert!(
                err.to_string().contains("cannot deserialize tagged scalar"),
                "{doc} -> {err}"
            );
        }
        // Matching tags still pass; `!!str` and `!` are string-compatible.
        assert_eq!(parse_field::<u16>("port: !!int 7890").unwrap(), 7890);
        assert_eq!(parse_field::<u16>("port: !!int \"7890\"").unwrap(), 7890);
        assert_eq!(parse_field::<String>("secret: !!str 42").unwrap(), "42");
        assert_eq!(parse_field::<String>("secret: ! 42").unwrap(), "42");
        // A matching `!!bool` on a bool target passes.
        assert!(parse_field::<bool>("ipv6: !!bool true").unwrap());
    }

    /// An `!!int`-tagged key into a `String`-keyed map failed the direct
    /// path's `can_parse_into_string` check — same here.
    #[test]
    fn tagged_key_rejected() {
        let err = parse_map::<String>("{!!int 42: a}").expect_err("!!int key should fail");
        assert!(err.to_string().contains("cannot deserialize tagged scalar"));
    }

    /// Tuples get an exact length check: a longer sequence is rejected
    /// even though no `Raw*` field currently drives this path.
    #[test]
    fn tuple_length_enforced() {
        let err = parse_field::<(u16, u16)>("x: [1, 2, 3]").expect_err("extra element");
        assert!(err.to_string().contains("invalid length"), "{err}");
        // Both shorter and longer sequences fail; only the exact length passes.
        assert!(parse_field::<(u16, u16)>("x: [1]").is_err());
        assert_eq!(parse_field::<(u16, u16)>("x: [1, 2]").unwrap(), (1, 2));
        // Tuple-struct path shares the check.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Pair(u16, u16);
        assert!(parse_field::<Pair>("x: [1, 2, 3]").is_err());
        assert!(parse_field::<Pair>("x: [1, 2]").is_ok());
    }

    /// A key-side failure (here: a `~` key into a `String` map) reports
    /// the *key's* position now that keys carry their own span.
    #[test]
    fn key_error_uses_key_location() {
        let err = parse_map::<String>("a: 1\n~: 2\n").expect_err("null key should fail");
        assert!(err.to_string().starts_with("line 2 column 1"), "{err}");
    }
}
