// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic and partition expression matching of the governance and
//! permissions documents.
//!
//! DDS-Security v1.1 Sec.9.4.1.2.6.1 (governance topic expressions),
//! Sec.9.4.1.3.2.3.1.3 (permissions topic expressions) and
//! Sec.9.4.1.3.2.3.1.4 (partition expressions): "The ... name expression
//! syntax and matching shall use the syntax and rules of the POSIX fnmatch()
//! function as specified in POSIX 1003.2-1992, Section B.6." No flag is
//! named, so the flags are none: `*` matches any string, `/` included
//! (FNM_PATHNAME is not set), a leading `.` is not special (FNM_PERIOD is not
//! set), and a backslash quotes the character after it (FNM_NOESCAPE is not
//! set); a backslash ending the pattern quotes nothing and matches nothing.
//!
//! One matcher for every document: `*`, `?`, backslash quoting and bracket
//! expressions with `!` (and glibc's `^`) negation, ranges, a leading `]`,
//! character classes (`[:alpha:]` and the eleven others), equivalence
//! classes (`[=a=]`) and collating symbols (`[.a.]`). A bracket that is never
//! closed is an ordinary `[`.
//!
//! The locale is the "C" (POSIX) locale, the one a process runs in until it
//! calls `setlocale`: the pattern and the name are matched as glibc's
//! `fnmatch(pattern, name, 0)` matches them there (posix/fnmatch_loop.c,
//! glibc 2.41, quirks included), BYTE by byte - the specification names no
//! locale, and this one is the same on every host. A character outside
//! ASCII is the bytes of its UTF-8 encoding: `?` matches one byte of it
//! (`?` does not match `\u{e9}`, `??` does), a bracket element is one byte
//! and a range compares bytes, a character class holds no byte above 0x7F,
//! an equivalence class or a collating symbol names one byte (a
//! multi-byte character there is a multi-character collating symbol, refused
//! at load). glibc in a UTF-8 locale (C.UTF-8, en_US.UTF-8) matches by
//! character instead; the two agree on every ASCII pattern and name.
//!
//! A pattern holding a bracket element glibc gives up on (an unknown class
//! name such as `[:uper:]`, a collating symbol of more than one character, a
//! bracket cut short after a backslash) is refused when the document is
//! loaded ([`check_pattern`]): glibc matches no name with it, except one an
//! earlier element of the same bracket happens to match before glibc reads
//! the ill-formed one. A typo in a deny rule would deny nothing.
//!
//! Bounded: matching costs at most a product of the pattern's length and
//! the name's (one backtrack point, the last star), and a pattern longer
//! than [`MAX_PATTERN_LENGTH`] bytes is refused when the document is loaded.

// A step counter for the test suite's bound check, so a test can assert on
// how much WORK a match did instead of how long it took: a wall-clock bound
// turns into a false failure under CPU load (another process stealing the
// core mid-match), while a count of the elementary steps `matches_from` and
// `bracket` took is exact regardless of how fast or slow the core was that
// ran them. `#[cfg(not(test))]` compiles the counting calls below to
// nothing, so this costs the real matcher nothing.
#[cfg(test)]
thread_local! {
    static STEP_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_step_count() {
    STEP_COUNT.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn step_count() -> u64 {
    STEP_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
#[inline(always)]
fn count_step() {
    STEP_COUNT.with(|c| c.set(c.get() + 1));
}

// @audit-ok: deliberately empty -- this is the real matcher's build of the
// counting call sites, compiled to nothing so the test-only instrumentation
// above costs it nothing.
#[cfg(not(test))]
#[inline(always)]
fn count_step() {}

/// Longest character class name glibc reads (`CHARCLASS_NAME_MAX`).
const CHAR_CLASS_MAX_LENGTH: usize = 2048;

/// Longest expression a governance or permissions document may hold, in
/// bytes ([`check_pattern`]): far above any real topic or partition
/// expression, and it caps what one match can cost.
pub const MAX_PATTERN_LENGTH: usize = 4096;

/// Longest name [`fnmatch`] matches against a pattern, in bytes.
///
/// `pattern` comes from a document this participant loaded and trusts
/// enough to bound at load time ([`check_pattern`]). `name` is a topic or
/// partition name a REMOTE PEER announced over SEDP, and nothing upstream
/// bounds it to anything smaller than the wire allows: the module's own
/// worst case is a product of the two lengths, so a pattern at the load-time
/// cap matched against an unbounded name is not bounded at all. Far above
/// any real topic or partition name, and refusing the match outright (never
/// a partial compare, never a truncation that could accidentally agree with
/// a real name) is the one door this is enforced at - [`fnmatch`] is called
/// nowhere else.
pub const MAX_NAME_LENGTH: usize = 4096;

/// Refuse a pattern longer than [`MAX_PATTERN_LENGTH`] bytes, or holding a
/// bracket expression glibc reads as ill-formed (see the module
/// documentation): its class name unknown, its collating symbol longer than
/// one byte or never closed, a backslash or a range cut by the end of the
/// pattern.
pub fn check_pattern(pattern: &str) -> Result<(), String> {
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(format!(
            "expression of {} bytes refused: longer than {} bytes",
            pattern.len(),
            MAX_PATTERN_LENGTH
        ));
    }
    let bytes = pattern.as_bytes();
    let mut p = 0usize;
    while p < bytes.len() {
        match bytes[p] {
            b'\\' => p += 2,
            b'[' => match bracket(bytes, p, None) {
                Bracket::Next(next) | Bracket::Missed(next) => p = next,
                Bracket::Literal => p += 1,
                Bracket::IllFormed => {
                    return Err(format!(
                        "expression \"{}\" holds an ill-formed bracket expression (an unknown \
                         character class, a collating symbol of more than one character, or a \
                         bracket cut short): fnmatch() gives up on it",
                        pattern
                    ))
                }
            },
            _ => p += 1,
        }
    }
    Ok(())
}

/// Whether `name` matches `pattern` as `fnmatch(pattern, name, 0)` decides
/// in the "C" locale, byte by byte (see the module documentation).
///
/// A `name` longer than [`MAX_NAME_LENGTH`] never matches, whatever
/// `pattern` is: no real topic or partition name is anywhere near that
/// long, and refusing the match bounds the cost of a peer that announces
/// one that is (see [`MAX_NAME_LENGTH`]).
#[must_use]
pub fn fnmatch(pattern: &str, name: &str) -> bool {
    if name.len() > MAX_NAME_LENGTH {
        return false;
    }
    matches_from(pattern.as_bytes(), name.as_bytes())
}

fn matches_from(pattern: &[u8], name: &[u8]) -> bool {
    // Iterative with one backtrack point per `*`: the last star seen and the
    // name position it was tried at. A later failure retries that star one
    // character further. Linear in practice, never exponential.
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        count_step();
        if p < pattern.len() {
            match pattern[p] {
                b'*' => {
                    star = Some((p, n));
                    p += 1;
                    continue;
                }
                b'?' => {
                    p += 1;
                    n += 1;
                    continue;
                }
                b'[' => match bracket(pattern, p, Some(name[n])) {
                    Bracket::Next(next) => {
                        p = next;
                        n += 1;
                        continue;
                    }
                    // Never closed: an ordinary '['.
                    Bracket::Literal if name[n] == b'[' => {
                        p += 1;
                        n += 1;
                        continue;
                    }
                    _ => {}
                },
                // A backslash ending the pattern quotes nothing and matches
                // no character, itself included (glibc: no match).
                b'\\' if p + 1 == pattern.len() => {}
                b'\\' => {
                    if pattern[p + 1] == name[n] {
                        p += 2;
                        n += 1;
                        continue;
                    }
                }
                c => {
                    if c == name[n] {
                        p += 1;
                        n += 1;
                        continue;
                    }
                }
            }
        }
        // Mismatch: retry the last star one character further, or fail.
        match star {
            Some((sp, sn)) => {
                star = Some((sp, sn + 1));
                p = sp + 1;
                n = sn + 1;
            }
            None => return false,
        }
    }
    // The name is consumed: only stars may remain.
    pattern[p..].iter().all(|&c| c == b'*')
}

/// What a bracket expression says about one character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bracket {
    /// It matches; the pattern continues at this index.
    Next(usize),
    /// It does not match; the bracket ends before this index.
    Missed(usize),
    /// Never closed: the `[` is an ordinary character.
    Literal,
    /// Ill-formed where glibc gives up: no character matches here.
    IllFormed,
}

/// The "C"-locale character class `name`, or `None` for a name glibc's
/// `wctype` does not know. No byte above 0x7F belongs to any.
fn class(name: &[u8]) -> Option<fn(u8) -> bool> {
    Some(match name {
        b"alnum" => |c: u8| c.is_ascii_alphanumeric(),
        b"alpha" => |c: u8| c.is_ascii_alphabetic(),
        b"blank" => |c: u8| c == b' ' || c == b'\t',
        b"cntrl" => |c: u8| c.is_ascii_control(),
        b"digit" => |c: u8| c.is_ascii_digit(),
        b"graph" => |c: u8| c.is_ascii_graphic(),
        b"lower" => |c: u8| c.is_ascii_lowercase(),
        b"print" => |c: u8| c.is_ascii_graphic() || c == b' ',
        b"punct" => |c: u8| c.is_ascii_punctuation(),
        // isspace: space, \t \n \v \f \r (Rust's is_ascii_whitespace omits \v).
        b"space" => |c: u8| c == b' ' || (b'\t'..=b'\r').contains(&c),
        b"upper" => |c: u8| c.is_ascii_uppercase(),
        b"xdigit" => |c: u8| c.is_ascii_hexdigit(),
        _ => return None,
    })
}

/// The collating symbol `[.x.]` whose `[` is at `pattern[open]` (its `.` at
/// `open + 1`): the one character it names and the index after its `.]`.
/// `None` when it is never closed or names more than one byte (the "C"
/// locale defines no multi-character collating element).
fn collating_symbol(pattern: &[u8], open: usize) -> Option<(u8, usize)> {
    let mut p = open + 1;
    let mut length = 0usize;
    loop {
        p += 1;
        let c = *pattern.get(p)?;
        if c == b'.' && pattern.get(p + 1) == Some(&b']') {
            break;
        }
        length += 1;
    }
    (length == 1).then(|| (pattern[open + 2], p + 2))
}

/// The bracket expression opening at `pattern[open]`, tested against `c`
/// (`None`: against no character, to walk it, `check_pattern`). A port of
/// the bracket case of glibc 2.41 `internal_fnmatch` (posix/fnmatch_loop.c)
/// for flags 0 and a locale with no collation rules, step for step: each
/// element is read in the order glibc reads it, so that the index the
/// pattern continues at, and the elements glibc gives up on, are glibc's.
#[allow(clippy::too_many_lines)]
fn bracket(pattern: &[u8], open: usize, c: Option<u8>) -> Bracket {
    let at = |i: usize| pattern.get(i).copied();
    let mut p = open + 1;
    // glibc negates on '^' too (unless POSIXLY_CORRECT is set).
    let negate = matches!(at(p), Some(b'!' | b'^'));
    if negate {
        p += 1;
    }
    // `cur` is the element character being read, `p` the index after it.
    let mut cur = at(p);
    p += 1;
    let matched = 'elements: loop {
        count_step();
        // The lower end of a possible range, once the element is read.
        let low: u8;
        match cur {
            None => return Bracket::Literal,
            Some(b'\\') => {
                let Some(quoted) = at(p) else {
                    return Bracket::IllFormed;
                };
                p += 1;
                if plain_element(pattern, p, quoted, c) {
                    break 'elements true;
                }
                low = quoted;
            }
            Some(b'[') if at(p) == Some(b':') => {
                let start = p;
                let mut name = Vec::new();
                let mut is_class = true;
                loop {
                    if name.len() == CHAR_CLASS_MAX_LENGTH {
                        return Bracket::IllFormed;
                    }
                    p += 1;
                    match at(p) {
                        Some(b':') if at(p + 1) == Some(b']') => {
                            p += 2;
                            break;
                        }
                        // glibc: `c < 'a' || c >= 'z'` cannot be a class name,
                        // so 'z' itself ends it (no class name holds one).
                        Some(letter) if (b'a'..=b'y').contains(&letter) => name.push(letter),
                        _ => {
                            is_class = false;
                            break;
                        }
                    }
                }
                if is_class {
                    let Some(test) = class(&name) else {
                        return Bracket::IllFormed;
                    };
                    if c.is_some_and(test) {
                        break 'elements true;
                    }
                    cur = at(p);
                    p += 1;
                    if cur == Some(b']') {
                        break 'elements false;
                    }
                    continue 'elements;
                }
                // Not a class: '[' read as an ordinary character.
                p = start;
                if plain_element(pattern, p, b'[', c) {
                    break 'elements true;
                }
                low = b'[';
            }
            Some(b'[') if at(p) == Some(b'=') => {
                let start = p;
                let named = at(p + 1);
                let closed = named.is_some() && at(p + 2) == Some(b'=') && at(p + 3) == Some(b']');
                if closed {
                    p += 4;
                    if c.is_some() && c == named {
                        break 'elements true;
                    }
                    cur = at(p);
                    p += 1;
                    if cur == Some(b']') {
                        break 'elements false;
                    }
                    continue 'elements;
                }
                p = start;
                if plain_element(pattern, p, b'[', c) {
                    break 'elements true;
                }
                low = b'[';
            }
            Some(b'[') if at(p) == Some(b'.') => {
                let Some((symbol, next)) = collating_symbol(pattern, p - 1) else {
                    return Bracket::IllFormed;
                };
                p = next;
                let is_range = at(p) == Some(b'-') && at(p + 1).is_some();
                if !is_range && c == Some(symbol) {
                    break 'elements true;
                }
                low = symbol;
            }
            Some(ch) => {
                if plain_element(pattern, p, ch, c) {
                    break 'elements true;
                }
                low = ch;
            }
        }
        // After the element: `p` is at the character following it.
        cur = at(p);
        p += 1;
        if cur == Some(b'-') && at(p) != Some(b']') {
            let mut high = at(p);
            p += 1;
            if high == Some(b'[') && at(p) == Some(b'.') {
                let Some((symbol, next)) = collating_symbol(pattern, p - 1) else {
                    return Bracket::IllFormed;
                };
                p = next;
                high = Some(symbol);
            } else {
                if high == Some(b'\\') {
                    high = at(p);
                    p += 1;
                }
                if high.is_none() {
                    return Bracket::IllFormed;
                }
            }
            if let (Some(c), Some(high)) = (c, high) {
                if low <= c && c <= high {
                    break 'elements true;
                }
            }
            cur = at(p);
            p += 1;
        }
        if cur == Some(b']') {
            break 'elements false;
        }
    };
    if !matched {
        return if negate {
            Bracket::Next(p)
        } else {
            Bracket::Missed(p)
        };
    }
    // Matched: skip the rest of the bracket, as glibc does.
    loop {
        let skipped = at(p);
        p += 1;
        match skipped {
            Some(b']') => break,
            None => return Bracket::Literal,
            Some(b'\\') => {
                if at(p).is_none() {
                    return Bracket::IllFormed;
                }
                p += 1;
            }
            Some(b'[') if at(p) == Some(b':') => {
                let start = p;
                let mut length = 0usize;
                loop {
                    p += 1;
                    length += 1;
                    if length == CHAR_CLASS_MAX_LENGTH {
                        return Bracket::IllFormed;
                    }
                    if at(p) == Some(b':') && at(p + 1) == Some(b']') {
                        break;
                    }
                    // As above: 'a' to 'y', glibc's `c < 'a' || c >= 'z'`.
                    if !at(p).is_some_and(|letter| (b'a'..=b'y').contains(&letter)) {
                        p = start - 2;
                        break;
                    }
                }
                p += 2;
            }
            Some(b'[') if at(p) == Some(b'=') => {
                if at(p + 1).is_none() || at(p + 2) != Some(b'=') || at(p + 3) != Some(b']') {
                    return Bracket::IllFormed;
                }
                p += 4;
            }
            Some(b'[') if at(p) == Some(b'.') => loop {
                p += 1;
                match at(p) {
                    None => return Bracket::IllFormed,
                    Some(b'.') if at(p + 1) == Some(b']') => {
                        p += 2;
                        break;
                    }
                    _ => {}
                }
            },
            Some(_) => {}
        }
    }
    if negate {
        Bracket::Missed(p)
    } else {
        Bracket::Next(p)
    }
}

/// An ordinary element `ch` of a bracket, `p` at the character after it
/// (glibc's `normal_bracket`): whether it alone matches `c` (it does not
/// open a range).
fn plain_element(pattern: &[u8], p: usize, ch: u8, c: Option<u8>) -> bool {
    let is_range =
        pattern.get(p) == Some(&b'-') && pattern.get(p + 1).is_some_and(|&next| next != b']');
    !is_range && c == Some(ch)
}

#[cfg(test)]
mod tests {
    use super::fnmatch;

    /// The four expressions of the specification's example governance
    /// document (Sec.9.4.1.2.8): `Square*`, `Circle`, `Triangle`, `*`.
    #[test]
    fn the_specification_example_expressions() {
        assert!(fnmatch("Square*", "Square"));
        assert!(fnmatch("Square*", "SquareRoot"));
        assert!(!fnmatch("Square*", "ASquare"));
        assert!(fnmatch("Circle", "Circle"));
        assert!(!fnmatch("Circle", "Circles"));
        assert!(!fnmatch("Circle", "circle"), "case-sensitive");
        assert!(fnmatch("*", ""));
        assert!(fnmatch("*", "anything/at/all"));
    }

    /// No FNM_PATHNAME: a star crosses '/'.
    #[test]
    fn a_star_crosses_a_slash_and_a_leading_dot() {
        assert!(fnmatch("rt/*", "rt/a/b"));
        assert!(fnmatch("*/temperature", "a/b/temperature"));
        assert!(fnmatch("*", ".hidden"), "no FNM_PERIOD");
        assert!(!fnmatch("sensor/*", "sensorAdmin"));
    }

    #[test]
    fn question_marks_and_brackets() {
        assert!(fnmatch("T?pic", "Topic"));
        assert!(!fnmatch("T?pic", "Tpic"));
        assert!(fnmatch("Topic[0-9]", "Topic7"));
        assert!(!fnmatch("Topic[0-9]", "TopicA"));
        assert!(fnmatch("Topic[!0-9]", "TopicA"));
        assert!(!fnmatch("Topic[!0-9]", "Topic7"));
        assert!(fnmatch("[]x]", "]"));
        assert!(fnmatch("[a-]", "-"), "a trailing '-' is literal");
        assert!(
            fnmatch("a[", "a["),
            "an unclosed bracket is an ordinary '['"
        );
        assert!(!fnmatch("a[", "ab"));
    }

    #[test]
    fn a_backslash_quotes_the_next_character() {
        assert!(fnmatch(r"a\*b", "a*b"));
        assert!(!fnmatch(r"a\*b", "axb"));
        assert!(fnmatch(r"a\?", "a?"));
        assert!(!fnmatch(r"a\?", "ab"));
    }

    /// Backtracking: the first star has to give characters back.
    #[test]
    fn stars_backtrack() {
        assert!(fnmatch("*a*b", "xxaxxb"));
        assert!(fnmatch("a*b*c", "abbbc"));
        assert!(!fnmatch("a*b*c", "abbb"));
        assert!(fnmatch("**", "x"));
        assert!(!fnmatch("*x", "y"));
    }

    /// Character classes, equivalence classes and collating symbols are
    /// matched, as glibc matches them in the POSIX locale.
    #[test]
    fn bracket_classes_are_matched() {
        assert!(fnmatch("[[:upper:]]quare", "Square"));
        assert!(!fnmatch("[[:upper:]]quare", "square"));
        assert!(fnmatch("Topic[[:digit:]]", "Topic7"));
        assert!(!fnmatch("Topic[![:digit:]]", "Topic7"));
        assert!(fnmatch("[[=a=]]", "a"));
        assert!(fnmatch("[[.-.]]", "-"));
        assert!(
            !fnmatch("[[:alpha:]]", "\u{e9}"),
            "POSIX locale: ASCII only"
        );
        assert!(
            fnmatch("[[:space:]]", "\u{b}"),
            "isspace includes the vertical tab"
        );
    }

    /// A bracket element glibc gives up on is refused at load; a valid one,
    /// and an unclosed bracket, are not.
    #[test]
    fn an_ill_formed_bracket_is_refused_at_load() {
        for refused in [
            "[[:uper:]]",
            "a*[[:foo:]]",
            "[[.ab.]]",
            "[[.",
            "[a\\",
            "[a-\\",
        ] {
            assert!(super::check_pattern(refused).is_err(), "{}", refused);
        }
        for accepted in [
            "[[:alpha:]]",
            "[[:upper:][:digit:]]",
            "[[=a=]]",
            "[[.a.]-c]",
            "Square*",
            "a[",
            "[[:",
            "[[:alpha]",
            "\\[[:foo:]]",
        ] {
            assert!(super::check_pattern(accepted).is_ok(), "{}", accepted);
        }
    }

    /// `fnmatch(pattern, name, 0)` as glibc answers it in the "C" locale,
    /// case by case. The table was computed with glibc 2.41's own fnmatch
    /// (flags 0; the ASCII rows agree under C.UTF-8, the non-ASCII ones are
    /// the "C" answers). Every row is matched, those `check_pattern` refuses
    /// at load included. The bracket port was also compared with glibc on
    /// 2.7 million generated (pattern, name) pairs, with no difference.
    #[test]
    fn matches_glibc_fnmatch_with_no_flags() {
        let cases: &[(&str, &str, bool)] = &[
            ("*", "a/b", true),
            ("*", "", true),
            ("?", "", false),
            ("a\\", "a\\", false),
            ("a\\", "a", false),
            ("\\*", "*", true),
            ("\\*", "a", false),
            ("[!]]", "a", true),
            ("[!]]", "]", false),
            ("[]a]", "]", true),
            ("[]a]", "a", true),
            ("[a-]", "-", true),
            ("[a-]", "b", false),
            ("a[", "a[", true),
            ("a[b", "a[b", true),
            ("[z-a]", "m", false),
            ("[z-a]", "z", false),
            ("Sq*", "square", false),
            ("*/x", "a/b/x", true),
            (".*", ".hidden", true),
            ("[\\]]", "]", true),
            ("[\\!a]", "!", true),
            ("[a\\-z]", "-", true),
            ("[a\\-z]", "m", false),
            ("[!a-c]", "d", true),
            ("**a", "bba", true),
            ("[[]", "[", true),
            ("[", "[", true),
            ("a*b?c", "axxbyc", true),
            ("\\", "\\", false),
            ("[a", "[", false),
            ("[a", "a", false),
            ("[a", "[a", true),
            ("[]", "]", false),
            ("[]", "[]", true),
            ("[!]", "!", false),
            ("[!]", "[!]", true),
            ("*[", "ab[", true),
            ("a*\\", "ab\\", false),
            ("\u{e9}?", "\u{e9}a", true),
            // "C" locale: a character outside ASCII is its UTF-8 bytes.
            ("?", "\u{e9}", false),
            ("??", "\u{e9}", true),
            // Character classes, equivalence classes, collating symbols.
            ("[[:upper:]]quare", "Square", true),
            ("[[:upper:]]quare", "square", false),
            ("[[:lower:]]*", "abc", true),
            ("[[:lower:]]*", "Abc", false),
            ("[[:alpha:]]", "_", false),
            ("[[:digit:]]", "5", true),
            ("[[:digit:]]", "a", false),
            ("[[:alnum:]]", "_", false),
            ("[[:space:]]", " ", true),
            ("[[:blank:]]", "x", false),
            ("[[:punct:]]", "/", true),
            ("[[:punct:]]", "a", false),
            ("[[:xdigit:]]", "F", true),
            ("[[:xdigit:]]", "g", false),
            ("[[:graph:]]", " ", false),
            ("[[:print:]]", " ", true),
            ("[![:digit:]]", "a", true),
            ("[![:digit:]]", "1", false),
            ("[^[:digit:]]", "1", false),
            ("[a[:digit:]]", "7", true),
            ("[a[:digit:]]", "b", false),
            ("[[:upper:][:digit:]]", "Q", true),
            ("[[:upper:][:digit:]]", "q", false),
            ("[[:digit:]-z]", "-", true),
            ("[[:digit:]-z]", "y", false),
            ("[[:digit:]-z]", "z", true),
            ("[a-[:digit:]]", "b", false),
            ("[[:alpha]", "p", true),
            ("[[:alpha]]", "a]", true),
            ("[[:alpha:\\]]", "a", true),
            ("[[:alpha\\:]]", "a", false),
            ("[[:", "[[:", true),
            ("[[=a=]]", "a", true),
            ("[[=a=]]", "b", false),
            ("[[=]", "=", true),
            ("[[=]=]]", "]", true),
            ("[[.a.]]", "a", true),
            ("[[.-.]]", "-", true),
            ("[[.a.]-c]", "b", true),
            ("[[.a.]-[.c.]]", "b", true),
            ("[[.].]]", "]", true),
            ("[[.!.]]", "!", true),
            ("[![.!.]]", "a", true),
            ("[a[.ab.]]", "a", true),
            ("[[:alpha:]-]", "-", true),
            ("a[[:digit:]]*", "a5x", true),
            ("[[:alpha:]]", "\u{e9}", false),
            ("[[:upper:]]", "", false),
            ("[[:foo:]]", "f", false),
            ("*[[:foo:]]", "x", false),
            ("[[.ab.]]", "a", false),
            ("[[.", "x", false),
            ("[a\\\\", "a", false),
            ("[[:alpha:]", "[", false),
            ("[^a]", "b", true),
            ("[[:z:]]", "z]", true),
            ("[[.a.]-]", "a", false),
            ("[[.a.]-]", "-", true),
            ("[a[:]b]", "ab]", true),
            ("[a-c]", "c", true),
            ("[[.a.]-c]", "c", true),
            ("[a-[.c.]]", "c", true),
        ];
        let mut diffs = Vec::new();
        for (pattern, name, want) in cases {
            let got = fnmatch(pattern, name);
            if got != *want {
                diffs.push(format!(
                    "fnmatch({:?}, {:?}) = {} but glibc = {}",
                    pattern, name, got, want
                ));
            }
        }
        assert!(diffs.is_empty(), "{:#?}", diffs);
    }

    /// Outside ASCII the "C" locale matches bytes: `?` and a bracket element
    /// are one byte of a UTF-8 character, a range compares bytes, a class
    /// holds none of them. Each row is also asked of the host's glibc
    /// fnmatch(3) (the process locale is "C": Rust never calls setlocale).
    #[test]
    fn outside_ascii_the_c_locale_matches_bytes() {
        let cases: &[(&str, &str, bool)] = &[
            ("?", "\u{e9}", false),
            ("??", "\u{e9}", true),
            ("???", "\u{20ac}", true),
            ("caf?", "caf\u{e9}", false),
            ("caf*", "caf\u{e9}", true),
            ("caf\u{e9}", "caf\u{e9}", true),
            ("[\u{e9}]", "\u{e9}", false),
            ("[\u{e9}]?", "\u{e9}", true),
            ("[!\u{e9}]", "\u{e9}", false),
            ("[!a]?", "\u{e9}", true),
            ("[a-\u{ff}]", "\u{e9}", false),
            ("[a-\u{ff}]?", "\u{e9}", true),
            ("[[:alpha:]]?", "\u{e9}", false),
            ("[![:alpha:]]?", "\u{e9}", true),
            ("[[:print:]]*", "\u{e9}", false),
        ];
        for (pattern, name, want) in cases {
            assert_eq!(
                fnmatch(pattern, name),
                *want,
                "fnmatch({pattern:?}, {name:?})"
            );
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            assert_eq!(
                glibc(pattern, name),
                *want,
                "the host's glibc on ({pattern:?}, {name:?})"
            );
        }
    }

    /// The host's glibc fnmatch(3), flags 0, in the process locale. The
    /// oracle exists only where the C library is glibc.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn glibc(pattern: &str, name: &str) -> bool {
        let pattern = std::ffi::CString::new(pattern).expect("no NUL");
        let name = std::ffi::CString::new(name).expect("no NUL");
        // SAFETY: two valid NUL-terminated C strings, alive for the call.
        unsafe { libc::fnmatch(pattern.as_ptr(), name.as_ptr(), 0) == 0 }
    }

    /// A multi-byte character in a collating symbol names more than one
    /// byte: refused at load, as glibc gives up on it.
    #[test]
    fn a_multi_byte_collating_symbol_is_refused_at_load() {
        assert!(super::check_pattern("[[.\u{e9}.]]").is_err());
        assert!(super::check_pattern("[[.e.]]").is_ok());
        assert!(!fnmatch("[[.\u{e9}.]]", "\u{e9}"));
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        assert!(!glibc("[[.\u{e9}.]]", "\u{e9}"));
    }

    /// An expression longer than `MAX_PATTERN_LENGTH` bytes is refused at
    /// load, one at the bound is not.
    #[test]
    fn the_pattern_length_is_bounded_at_load() {
        use super::MAX_PATTERN_LENGTH;
        assert!(super::check_pattern(&"a".repeat(MAX_PATTERN_LENGTH)).is_ok());
        assert!(super::check_pattern(&"a".repeat(MAX_PATTERN_LENGTH + 1)).is_err());
        // Bytes, not characters.
        let two_byte = "\u{e9}".repeat(MAX_PATTERN_LENGTH / 2);
        assert!(super::check_pattern(&two_byte).is_ok());
        assert!(super::check_pattern(&format!("{two_byte}a")).is_err());
    }

    /// `MAX_NAME_LENGTH`: unlike `pattern`, `name` is never refused at load
    /// (it is not loaded from a document at all - it is whatever a remote
    /// peer announced as a topic or partition name over SEDP), so the one
    /// door it is bounded at is `fnmatch` itself. A name at the bound still
    /// matches the pattern that names it; one byte past never matches ANY
    /// pattern, `*` included. Mutant: delete the length check in `fnmatch`
    /// and the second assertion fails (an unbounded name matches `*` again).
    #[test]
    fn a_name_past_the_bound_never_matches() {
        use super::MAX_NAME_LENGTH;
        let at_bound = "a".repeat(MAX_NAME_LENGTH);
        assert!(
            fnmatch("*", &at_bound),
            "a name AT the bound is still matched normally"
        );
        assert!(
            fnmatch(&at_bound, &at_bound),
            "an exact match at the bound still matches"
        );
        let past_bound = "a".repeat(MAX_NAME_LENGTH + 1);
        assert!(
            !fnmatch("*", &past_bound),
            "a name past the bound must never match, not even the widest pattern"
        );
    }

    /// A pattern ending in a backslash quotes nothing: glibc matches no name
    /// against it, the name that is the same characters included.
    #[test]
    fn a_trailing_backslash_matches_nothing() {
        assert!(!fnmatch("a\\", "a\\"));
        assert!(!fnmatch("a\\", "a"));
        assert!(!fnmatch("\\", "\\"));
        assert!(!fnmatch("a*\\", "ab\\"));
        assert!(!fnmatch("*\\", ""));
    }

    /// xorshift, own generator (not the author's).
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn v3_next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn v3_glibc(pattern: &str, name: &str) -> Option<bool> {
        let p = std::ffi::CString::new(pattern).ok()?;
        let n = std::ffi::CString::new(name).ok()?;
        // SAFETY: two valid NUL-terminated strings.
        let r = unsafe { libc::fnmatch(p.as_ptr(), n.as_ptr(), 0) };
        Some(r == 0)
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn v3_corpus(seed: u64, pieces: &[&str], name_alphabet: &[&str], rounds: usize) -> Vec<String> {
        let mut st = seed;
        let mut diffs = Vec::new();
        let mut compared = 0usize;
        for _ in 0..rounds {
            let plen = (v3_next(&mut st) % 9) as usize;
            let mut pattern = String::new();
            for _ in 0..plen {
                pattern.push_str(pieces[(v3_next(&mut st) % pieces.len() as u64) as usize]);
            }
            if super::check_pattern(&pattern).is_err() {
                continue;
            }
            for _ in 0..6 {
                let nlen = (v3_next(&mut st) % 7) as usize;
                let mut name = String::new();
                for _ in 0..nlen {
                    name.push_str(
                        name_alphabet[(v3_next(&mut st) % name_alphabet.len() as u64) as usize],
                    );
                }
                let Some(g) = v3_glibc(&pattern, &name) else {
                    continue;
                };
                compared += 1;
                if fnmatch(&pattern, &name) != g && diffs.len() < 40 {
                    diffs.push(format!(
                        "fnmatch({:?}, {:?}) = {} glibc = {}",
                        pattern, name, !g, g
                    ));
                }
            }
        }
        eprintln!(
            "[verify3] compared {} pairs, {} diffs",
            compared,
            diffs.len()
        );
        diffs
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    const V3_PIECES: &[&str] = &[
        "a",
        "b",
        "A",
        "1",
        "*",
        "?",
        "[",
        "]",
        "!",
        "^",
        "-",
        "\\",
        ":",
        ".",
        "=",
        "/",
        " ",
        "[:alpha:]",
        "[:digit:]",
        "[:upper:]",
        "[:space:]",
        "[:punct:]",
        "[:xdigit:]",
        "[=a=]",
        "[.a.]",
        "[.-.]",
        "[a-c]",
        "[!a]",
        "[]",
        "[^",
        "z",
        "[:",
        ":]",
    ];
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    const V3_NAMES: &[&str] = &[
        "a", "b", "A", "1", "[", "]", "!", "^", "-", "\\", ":", ".", "=", "/", " ", "z", "\t", "*",
        "?",
    ];

    /// Differential vs the host's glibc fnmatch(3), flags 0, in the process
    /// locale (Rust never calls setlocale: "C"), ASCII corpus.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn verify3_fnmatch_matches_glibc_ascii_random() {
        let diffs = v3_corpus(0x9E37_79B9_7F4A_7C15, V3_PIECES, V3_NAMES, 400_000);
        assert!(diffs.is_empty(), "{:#?}", diffs);
    }

    /// Same, names and patterns holding non-ASCII characters, still in the
    /// "C" locale (byte-wise glibc): `?` is one byte there.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn verify3_fnmatch_matches_glibc_non_ascii_c_locale() {
        let pieces: Vec<&str> = V3_PIECES
            .iter()
            .copied()
            .chain(["\u{e9}", "[\u{e9}]", "[a-\u{ff}]", "[!\u{e9}]"])
            .collect();
        let names: Vec<&str> = V3_NAMES
            .iter()
            .copied()
            .chain(["\u{e9}", "\u{20ac}"])
            .collect();
        let diffs = v3_corpus(0x0123_4567_89AB_CDEF, &pieces, &names, 200_000);
        assert!(diffs.is_empty(), "{:#?}", diffs);
    }

    /// Same in C.UTF-8 (setlocale: run ALONE, it changes the process locale).
    /// Expected to FAIL: the matcher is glibc's in the "C" locale, byte-wise
    /// (module documentation); C.UTF-8 matches by character. Kept to show
    /// where the two locales part.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    #[ignore = "changes the process locale, run alone; C.UTF-8 is not the matched locale"]
    fn verify3_fnmatch_matches_glibc_non_ascii_c_utf8() {
        let loc = std::ffi::CString::new("C.UTF-8").unwrap();
        // SAFETY: valid C string; test run alone.
        let r = unsafe { libc::setlocale(libc::LC_ALL, loc.as_ptr()) };
        assert!(!r.is_null(), "C.UTF-8 not available");
        let pieces: Vec<&str> = V3_PIECES
            .iter()
            .copied()
            .chain(["\u{e9}", "[\u{e9}]", "[a-\u{ff}]", "[!\u{e9}]"])
            .collect();
        let names: Vec<&str> = V3_NAMES
            .iter()
            .copied()
            .chain(["\u{e9}", "\u{20ac}"])
            .collect();
        let diffs = v3_corpus(0x0123_4567_89AB_CDEF, &pieces, &names, 200_000);
        let back = std::ffi::CString::new("C").unwrap();
        unsafe { libc::setlocale(libc::LC_ALL, back.as_ptr()) };
        assert!(diffs.is_empty(), "{:#?}", diffs);
    }

    /// Adversarial patterns: many stars, many brackets, long names. Bound:
    /// each case polynomial (O(name x pattern)), under 30 s debug.
    #[test]
    fn verify3_fnmatch_is_bounded_on_adversarial_patterns() {
        let name_a = "a".repeat(10_000);
        let cases: Vec<(String, String)> = vec![
            (format!("{}b", "*a".repeat(1_000)), name_a.clone()),
            (
                format!("*{}b", "[[:alpha:][:digit:]a-z]".repeat(200)),
                name_a.clone(),
            ),
            (format!("*[{}]b", "[:alpha:]".repeat(5_000)), name_a.clone()),
            (format!("{}*b", "*?".repeat(2_000)), name_a.clone()),
            (format!("*{}", "[!b]".repeat(3_000)), format!("{}b", name_a)),
        ];
        for (pattern, name) in cases {
            // Past MAX_PATTERN_LENGTH a document refuses it at load; the
            // matcher stays bounded all the same.
            assert_eq!(
                super::check_pattern(&pattern).is_ok(),
                pattern.len() <= super::MAX_PATTERN_LENGTH,
                "pattern len {}",
                pattern.len()
            );
            super::reset_step_count();
            let ours = fnmatch(&pattern, &name);
            let steps = super::step_count();
            eprintln!(
                "[verify3] pattern len {} name len {}: {} steps -> {}",
                pattern.len(),
                name.len(),
                steps,
                ours
            );
            // The module's own bound: at most a product of the pattern's
            // length and the name's (one backtrack point, the last star).
            // An operation count, not a wall-clock duration -- a core
            // another process is using at the same time slows the match
            // down without making it do more work, so counting steps is
            // the assertion that holds steady under CPU load while still
            // catching a real blow-up (the matcher turning quadratic into
            // something worse).
            let bound = 2 * (pattern.len() as u64) * (name.len() as u64) + 10_000;
            assert!(
                steps <= bound,
                "{steps} steps on pattern len {} name len {} (bound {bound})",
                pattern.len(),
                name.len()
            );
        }
    }
}
