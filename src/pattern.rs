//! A small, linear-time glob matcher used for argument and environment patterns.
//!
//! Supported syntax: `*` matches any sequence (including empty), `?` matches exactly one
//! character, and `\` escapes the next character. Everything else is literal. Matching is
//! anchored at both ends. There is no backtracking blow-up: the matcher uses the classic
//! two-pointer algorithm, which runs in `O(len(pattern) * len(text))` in the worst case.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Glob {
    source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Literal(char),
    Any,
    Star,
}

impl Glob {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    fn tokens(&self) -> Vec<Token> {
        let mut out = Vec::with_capacity(self.source.len());
        let mut chars = self.source.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => out.push(Token::Literal(chars.next().unwrap_or('\\'))),
                '*' => {
                    if out.last() != Some(&Token::Star) {
                        out.push(Token::Star);
                    }
                }
                '?' => out.push(Token::Any),
                other => out.push(Token::Literal(other)),
            }
        }
        out
    }

    pub fn matches(&self, text: &str) -> bool {
        let pattern = self.tokens();
        let text: Vec<char> = text.chars().collect();
        let (mut p, mut t) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while t < text.len() {
            match pattern.get(p) {
                Some(Token::Star) => {
                    star = Some((p, t));
                    p += 1;
                }
                Some(Token::Any) => {
                    p += 1;
                    t += 1;
                }
                Some(Token::Literal(c)) if *c == text[t] => {
                    p += 1;
                    t += 1;
                }
                _ => match star {
                    Some((sp, st)) => {
                        p = sp + 1;
                        t = st + 1;
                        star = Some((sp, st + 1));
                    }
                    None => return false,
                },
            }
        }
        pattern[p..].iter().all(|tok| *tok == Token::Star)
    }
}

impl From<&str> for Glob {
    fn from(value: &str) -> Self {
        Glob::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_wildcards() {
        assert!(Glob::new("ls").matches("ls"));
        assert!(!Glob::new("ls").matches("lsx"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("-*").matches("-la"));
        assert!(!Glob::new("-*").matches("la"));
        assert!(Glob::new("a?c").matches("abc"));
        assert!(!Glob::new("a?c").matches("ac"));
        assert!(Glob::new("*://*").matches("https://example.com"));
        assert!(Glob::new("LC_*").matches("LC_ALL"));
        assert!(Glob::new("a*b*c").matches("aXXbYYc"));
        assert!(!Glob::new("a*b*c").matches("aXXbYY"));
    }

    #[test]
    fn escapes_are_literal() {
        assert!(Glob::new(r"\*").matches("*"));
        assert!(!Glob::new(r"\*").matches("x"));
        assert!(Glob::new(r"a\?").matches("a?"));
        assert!(Glob::new("a\\").matches("a\\"));
    }

    #[test]
    fn unicode_is_matched_per_character() {
        assert!(Glob::new("?").matches("\u{00e9}"));
        assert!(Glob::new("*\u{ff0f}*").matches("a\u{ff0f}b"));
    }

    #[test]
    fn pathological_pattern_is_fast() {
        let pattern = Glob::new("a*a*a*a*a*a*a*a*a*b");
        let text = "a".repeat(5_000);
        let start = std::time::Instant::now();
        assert!(!pattern.matches(&text));
        assert!(start.elapsed().as_secs() < 2);
    }
}
