//! Send-destination patterns (PRD R-DST-6).
//!
//! The grammar is deliberately tiny: a literal string over a small alphabet,
//! optionally ending in `/*`, which matches exactly one more non-empty segment
//! containing no `/`. No other wildcard, no regex. It can be widened later;
//! it can never be narrowed once operators have config files.

use std::fmt;

/// A parsed, validated send pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// The literal part. For a wildcard pattern this is everything before `/*`.
    literal: String,
    /// True if the pattern ended in `/*`.
    wildcard: bool,
}

/// Why a pattern string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("pattern is empty")]
    Empty,
    #[error("pattern contains {0:?}, which is outside [A-Za-z0-9:_./+-] and `*`")]
    BadChar(char),
    #[error("`*` is only allowed as a final `/*` segment")]
    StarPlacement,
    #[error("wildcard pattern needs a non-empty literal before `/*`")]
    EmptyPrefix,
}

fn literal_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '/' | '+' | '-')
}

impl Pattern {
    /// Parse a pattern from operator config.
    pub fn parse(s: &str) -> Result<Self, PatternError> {
        if s.is_empty() {
            return Err(PatternError::Empty);
        }
        let (literal, wildcard) = match s.strip_suffix("/*") {
            Some(prefix) => (prefix, true),
            None => (s, false),
        };
        if wildcard && literal.is_empty() {
            return Err(PatternError::EmptyPrefix);
        }
        for c in literal.chars() {
            if c == '*' {
                return Err(PatternError::StarPlacement);
            }
            if !literal_char_ok(c) {
                return Err(PatternError::BadChar(c));
            }
        }
        Ok(Self {
            literal: literal.to_owned(),
            wildcard,
        })
    }

    /// Does a concrete target string match this pattern?
    ///
    /// Exact match for a literal pattern. For a wildcard pattern, the target
    /// must be `<literal>/<segment>` where `segment` is non-empty and contains
    /// no `/`. Case-sensitive.
    pub fn matches(&self, target: &str) -> bool {
        if !self.wildcard {
            return target == self.literal;
        }
        let Some(rest) = target.strip_prefix(self.literal.as_str()) else {
            return false;
        };
        let Some(segment) = rest.strip_prefix('/') else {
            return false;
        };
        !segment.is_empty() && !segment.contains('/')
    }

    /// True if the pattern ends in `/*`.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "{}/*", self.literal)
        } else {
            f.write_str(&self.literal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        Pattern::parse(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    // AT-26: pattern matcher table.
    #[test]
    fn literal_matches_exactly() {
        let pat = p("chat:group/team");
        assert!(pat.matches("chat:group/team"));
        assert!(!pat.matches("chat:group/team/"));
        assert!(!pat.matches("chat:group/teams"));
        assert!(!pat.matches("chat:group/tea"));
        assert!(!pat.matches("CHAT:group/team"));
        assert!(!pat.matches(""));
    }

    #[test]
    fn wildcard_matches_one_nonempty_segment() {
        let pat = p("chat:dm/*");
        assert!(pat.matches("chat:dm/+6421000000"));
        assert!(pat.matches("chat:dm/a"));
        assert!(!pat.matches("chat:dm/"), "empty segment");
        assert!(!pat.matches("chat:dm"), "prefix only");
        assert!(!pat.matches("chat:dm/a/b"), "extra segment");
        assert!(!pat.matches("chat:dmx/a"), "literal must be followed by /");
        assert!(!pat.matches("xchat:dm/a"));
    }

    #[test]
    fn wildcard_segment_may_contain_any_char_but_slash() {
        let pat = p("chat:dm/*");
        assert!(pat.matches("chat:dm/with space and ünïcode"));
        assert!(!pat.matches("chat:dm/with/slash"));
    }

    #[test]
    fn rejects_bad_patterns() {
        assert_eq!(Pattern::parse(""), Err(PatternError::Empty));
        assert_eq!(Pattern::parse("/*"), Err(PatternError::EmptyPrefix));
        assert_eq!(Pattern::parse("a*"), Err(PatternError::StarPlacement));
        assert_eq!(Pattern::parse("*"), Err(PatternError::StarPlacement));
        assert_eq!(Pattern::parse("a/*/b"), Err(PatternError::StarPlacement));
        assert_eq!(Pattern::parse("a/**"), Err(PatternError::StarPlacement));
        assert_eq!(Pattern::parse("a/*/*"), Err(PatternError::StarPlacement));
        assert_eq!(Pattern::parse("a b"), Err(PatternError::BadChar(' ')));
        assert_eq!(Pattern::parse("a?b"), Err(PatternError::BadChar('?')));
        assert_eq!(Pattern::parse("ünïcode"), Err(PatternError::BadChar('ü')));
    }

    #[test]
    fn display_round_trips() {
        for s in ["chat:group/team", "chat:dm/*", "a.b+c-d_e:f/g"] {
            assert_eq!(p(s).to_string(), s);
        }
    }
}
