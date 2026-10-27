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
use std::fmt;

/// One YAML node with its scalar's resolved type and, for containers, the
/// document order retained.
///
/// `Int` is `i128`: saphyr's `deserialize_any` reports plain YAML ints via
/// `visit_i64`/`visit_u64` (both fit `i128`), and anything wider already
/// arrives as `Float` — saphyr falls back to `f64` for u64-overflowing
/// literals. `Float` may be non-finite: `NonFiniteFloatPolicy::PassThrough`
/// in `yaml_options` hands `.inf`/`-.inf`/`.nan` and `f64`-overflowing
/// literals (`1e999`) through as IEEE values — matching what the direct
/// deserializer delivered to typed `f64` fields, and what
/// `serde_json::Value` flattens to `null` in its own subtrees.
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
    /// no span of their own — a key only feeds field-path segments and
    /// `expected string scalar` verdicts, for which the value node's
    /// location (same line in any real document) is the better span.
    Map(Vec<(YamlNode<'de>, SpannedNode<'de>)>),
}

impl YamlNode<'_> {
    /// The scalar's text in the form the direct saphyr deserializer fed
    /// typed field parsers — its `deserialize_u16` / `deserialize_bool` /
    /// `deserialize_string` all operated on the raw scalar text, so the
    /// scalar-typed field methods below do the same.
    ///
    /// Strings report verbatim. Resolved scalars report a canonical form:
    /// ints as decimal digits (`0x1F` arrives as `31`, `+7890` as `7890`),
    /// bools as `true`/`false` (a case-folded `TrUe` arrives as `true`),
    /// non-finite floats as `.nan`/`.inf`/`-.inf`, other floats via
    /// `f64`'s shortest `Display` (`0123`, resolved to `123.0`, reports as
    /// `123`). The raw spelling is unrecoverable once resolved — the one
    /// place that shows is a non-string scalar landing in a `String`
    /// field or a string-typed map key, which then sees the canonical
    /// text instead of the raw spelling (`+7`/`0x1F` arrive as `7`/`31`;
    /// pathological in practice — string-keyed maps hold domain/host
    /// names that stay `Str`).
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
                while let Some(key) = map.next_key::<YamlNode<'de>>()? {
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

/// A [`YamlNode`] paired with the locations saphyr exposes through its
/// `__yaml_spanned` newtype hook — the same data `serde_saphyr::Spanned`
/// yields, but captured with a lean drive of the synthesized map instead
/// of `Spanned`'s generic `Deserialize`: fixed-order zero-alloc field
/// checks, only `line`/`column` read out of each `Location` (early return
/// skips `span`/`source_id`), and no per-node `String` field buffer.
///
/// Relies on serde-saphyr 2.x internals — the `"__yaml_spanned"` newtype
/// name and the fixed `[marker, value, referenced, defined]` /
/// `[line, column, span, source_id]` field orders. Every step is checked
/// against the expected name, so a protocol change fails loudly here
/// rather than mislabeling locations.
#[derive(Debug)]
pub(crate) struct SpannedNode<'de> {
    pub node: YamlNode<'de>,
    /// Use-site (`referenced`) location — for an alias/merge-expanded
    /// node the `*`/`<<:` position. saphyr's `defined` field is left
    /// unread (the synthesized map is abandoned mid-drive): it only ever
    /// served as the fallback for a missing `referenced`, which saphyr
    /// always sets to the event's own location for a real node.
    pub loc: Loc,
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

impl<'de> serde::Deserialize<'de> for SpannedNode<'de> {
    /// `Spanned<T>` reaches the location-capture hook by naming the
    /// `__yaml_spanned` newtype; this does the same, then drives the
    /// synthesized `{marker, value, referenced, defined}` map directly.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SpannedVisitor;

        impl<'de> Visitor<'de> for SpannedVisitor {
            type Value = SpannedNode<'de>;

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
            type Value = SpannedNode<'de>;

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
                // `defined` deliberately unread — returning early leaves
                // the synthesized map access mid-drive, which it allows.
                Ok(SpannedNode { node, loc })
            }
        }

        deserializer.deserialize_newtype_struct("__yaml_spanned", SpannedVisitor)
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

/// The field-path segment a map key renders as.
fn key_segment(key: &YamlNode<'_>) -> String {
    match key.scalar_text() {
        Some(text) => text.into_owned(),
        None => node_kind(key).to_string(),
    }
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
/// - scalar→string coerces via the canonical scalar text (`secret: 123456`
///   → `"123456"`), and quoted strings parse into numeric/bool targets
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
/// - every error carries the node's `line/column` plus the field path
///   (`dns.fallback-filter.geoip`, `proxies[0].port`) accumulated by the
///   enclosing map/seq accesses;
/// - a non-mapping top node — including the previously accepted top-level
///   *sequence* — errors `expected mapping start`, closing the positional
///   struct-fill hole.
#[derive(Clone, Copy)]
struct NodeDe<'de> {
    node: &'de YamlNode<'de>,
    loc: Loc,
}

impl<'de> NodeDe<'de> {
    fn loc(&self) -> Loc {
        self.loc
    }

    fn err(&self, msg: impl Into<String>) -> TreeError {
        TreeError::new(self.loc(), msg)
    }

    fn scalar_text(&self) -> Option<Cow<'de, str>> {
        self.node.scalar_text()
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

    /// Unsigned-integer field value. `Int` range-checks (a negative `Int`
    /// fails exactly like a `-`-prefixed text did); `Str` parses its text
    /// (`port: "7890"`); `Float` fails outright — its source spelling
    /// always carried a `.`/`e`/`.nan`/`.inf` that the int parser rejects,
    /// and the canonical text (`1500` for `1500.0`) would lie; `Bool`/
    /// `Null` texts fail the parse the same way they did on the direct
    /// path.
    fn uint<T: TryFrom<u128>>(&self, ty: &'static str) -> Result<T, TreeError> {
        match &self.node {
            YamlNode::Int(v) => u128::try_from(*v)
                .ok()
                .and_then(|m| T::try_from(m).ok())
                .ok_or_else(|| self.invalid_scalar(ty)),
            YamlNode::Float(_) => Err(self.invalid_scalar(ty)),
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => parse_int_unsigned::<T>(&self.scalar_text().unwrap_or_default())
                .ok_or_else(|| self.invalid_scalar(ty)),
        }
    }

    /// Signed-integer field value; same rules as [`NodeDe::uint`].
    fn sint<T: TryFrom<i128>>(&self, ty: &'static str) -> Result<T, TreeError> {
        match &self.node {
            YamlNode::Int(v) => T::try_from(*v).map_err(|_| self.invalid_scalar(ty)),
            YamlNode::Float(_) => Err(self.invalid_scalar(ty)),
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => parse_int_signed::<T>(&self.scalar_text().unwrap_or_default())
                .ok_or_else(|| self.invalid_scalar(ty)),
        }
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

/// Shared scalar→string delivery: verbatim for `Str`, canonical text for
/// the resolved scalars — the coercion saphyr's typed string methods
/// applied to the scalar's source text.
fn visit_strlike<'de, V: Visitor<'de>>(
    de: &NodeDe<'de>,
    visitor: V,
) -> Result<V::Value, TreeError> {
    match &de.node {
        YamlNode::Str(s) => visitor
            .visit_borrowed_str(s.as_ref())
            .map_err(|e: TreeError| e.at(de.loc())),
        YamlNode::Int(_) | YamlNode::Bool(_) | YamlNode::Float(_) => visitor
            .visit_string(
                de.scalar_text()
                    .expect("numeric/bool nodes have scalar text")
                    .into_owned(),
            )
            .map_err(|e: TreeError| e.at(de.loc())),
        YamlNode::Null => Err(de.err("cannot deserialize null into string; use Option<String>")),
        YamlNode::Seq(_) | YamlNode::Map(_) => Err(de.expect_scalar()),
    }
}

impl<'de> de::Deserializer<'de> for NodeDe<'de> {
    type Error = TreeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match &self.node {
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
        match &self.node {
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
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
        match &self.node {
            YamlNode::Float(v) => visitor
                .visit_f64(*v)
                .map_err(|e: TreeError| e.at(self.loc())),
            YamlNode::Int(v) => visitor
                .visit_f64(*v as f64)
                .map_err(|e: TreeError| e.at(self.loc())),
            YamlNode::Seq(_) | YamlNode::Map(_) => Err(self.expect_scalar()),
            _ => {
                let text = self.scalar_text().unwrap_or_default();
                let v = parse_f64(&text).ok_or_else(|| self.invalid_scalar("floating point"))?;
                visitor
                    .visit_f64(v)
                    .map_err(|e: TreeError| e.at(self.loc()))
            }
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match &self.node {
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
        match &self.node {
            // A u8-element sequence, as saphyr accepted for byte targets.
            YamlNode::Seq(_) => self.deserialize_seq(visitor),
            YamlNode::Map(_) => Err(self.err("expected scalar (!!binary) or sequence of 0..=255")),
            _ => Err(self.err("bytes not supported (missing !!binary tag)")),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match &self.node {
            YamlNode::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
        .map_err(|e: TreeError| e.at(self.loc()))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match &self.node {
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
        match &self.node {
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
        match &self.node {
            YamlNode::Seq(items) => visitor
                .visit_seq(NodeSeqAcc {
                    iter: items.iter(),
                    idx: 0,
                })
                .map_err(|e: TreeError| e.at(loc)),
            // saphyr treated a null-like scalar as an empty sequence.
            YamlNode::Null => visitor
                .visit_seq(NodeSeqAcc {
                    iter: [].iter(),
                    idx: 0,
                })
                .map_err(|e: TreeError| e.at(loc)),
            _ => Err(self.err("expected sequence start")),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        match &self.node {
            YamlNode::Map(entries) => visitor
                .visit_map(NodeMapAcc {
                    iter: entries.iter(),
                    pending: None,
                })
                .map_err(|e: TreeError| e.at(loc)),
            // saphyr treated a null-like scalar as an empty mapping — this
            // is what normalizes an empty/`null` document into the
            // all-defaults `RawConfig`.
            YamlNode::Null => visitor
                .visit_map(NodeMapAcc {
                    iter: [].iter(),
                    pending: None,
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
        match &self.node {
            YamlNode::Seq(_) => Err(self.err("externally tagged enum expected scalar or mapping")),
            YamlNode::Map(entries) => match entries.as_slice() {
                [(key, value)] => visitor
                    .visit_enum(TreeEnumAccess {
                        variant: key,
                        loc: node_loc(value),
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
                    variant: self.node,
                    loc: self.loc,
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
        seed.deserialize(NodeDe {
            node: &node.node,
            loc: node_loc(node),
        })
        .map(Some)
        .map_err(|e| e.prepend(format!("[{idx}]")))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

/// `MapAccess` over a `YamlNode::Map`, in document order. The key's scalar
/// text becomes the path segment prepended to a value's escaping error —
/// rendered lazily so the no-error path allocates nothing per key.
struct NodeMapAcc<'de> {
    iter: std::slice::Iter<'de, (YamlNode<'de>, SpannedNode<'de>)>,
    /// `(value node, key node)` of the in-flight entry.
    pending: Option<(&'de SpannedNode<'de>, &'de YamlNode<'de>)>,
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
        self.pending = Some((value, key));
        seed.deserialize(KeyDe {
            node: key,
            loc: node_loc(value),
        })
        .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let Some((value, key)) = self.pending.take() else {
            return Err(de::Error::custom("value requested before key"));
        };
        seed.deserialize(NodeDe {
            node: &value.node,
            loc: node_loc(value),
        })
        .map_err(|e| e.prepend(key_segment(key)))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

/// A map *key* deserializer. Keys are scalars: any resolved scalar type
/// reports its canonical text (`123`, `true`, `1.5`, `.inf` keys all work,
/// as saphyr's stringified keys did); a `~`/empty key fails the
/// string-shaped requests, and a container key is `expected string
/// scalar`.
#[derive(Clone, Copy)]
struct KeyDe<'de> {
    node: &'de YamlNode<'de>,
    /// The *value* node's location — the key carries no span of its own,
    /// and a bad key sits on the value's line in any real document.
    loc: Loc,
}

impl<'de> KeyDe<'de> {
    fn loc(&self) -> Loc {
        self.loc
    }

    fn err(&self, msg: impl Into<String>) -> TreeError {
        TreeError::new(self.loc(), msg)
    }

    fn text(&self) -> Result<Cow<'de, str>, TreeError> {
        match self.node {
            YamlNode::Null => {
                Err(self.err("cannot deserialize null into string; use Option<String>"))
            }
            _ => self
                .node
                .scalar_text()
                .ok_or_else(|| self.err("expected string scalar")),
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
            node: self.node,
            loc: self.loc,
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
        match &self.node {
            YamlNode::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
        .map_err(|e: TreeError| e.at(self.loc()))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match &self.node {
            YamlNode::Null => visitor
                .visit_unit()
                .map_err(|e: TreeError| e.at(self.loc())),
            _ => Err(self.err("unexpected value for unit")),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let loc = self.loc();
        let text = self.text()?;
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
    variant: &'de YamlNode<'de>,
    loc: Loc,
    value: Option<&'de SpannedNode<'de>>,
}

impl<'de> EnumAccess<'de> for TreeEnumAccess<'de> {
    type Error = TreeError;
    type Variant = TreeVariantAccess<'de>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let value = self.value;
        seed.deserialize(KeyDe {
            node: self.variant,
            loc: self.loc,
        })
        .map(|variant| (variant, TreeVariantAccess { value }))
    }
}

struct TreeVariantAccess<'de> {
    value: Option<&'de SpannedNode<'de>>,
}

impl<'de> TreeVariantAccess<'de> {
    fn require_value(&self) -> Result<NodeDe<'de>, TreeError> {
        match self.value {
            Some(node) => Ok(NodeDe {
                node: &node.node,
                loc: node_loc(node),
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
pub(crate) fn deserialize_config<'de>(
    root: &'de SpannedNode<'de>,
) -> Result<crate::raw::RawConfig, TreeError> {
    <crate::raw::RawConfig as serde::Deserialize>::deserialize(NodeDe {
        node: &root.node,
        loc: node_loc(root),
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
            entries.iter().map(|(k, _)| k.scalar_text()).collect();
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
}
