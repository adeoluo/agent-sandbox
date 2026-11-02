//! Path handling: deceptive-character checks, placeholder expansion, and symlink-aware
//! resolution that defeats `..` and symlink escapes.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Maximum number of symlinks followed while resolving one path (matches Linux `MAXSYMLINKS`).
pub const MAX_SYMLINKS: usize = 40;

/// Characters that render like a path separator or dot but are not one. A path containing
/// them is not an escape by itself on Unix, but other layers (a UI, a log viewer, a Unicode
/// normalizer) may treat them as separators, so they are rejected outright.
const LOOKALIKES: &[char] = &[
    '\u{2215}', // DIVISION SLASH
    '\u{2044}', // FRACTION SLASH
    '\u{29F8}', // BIG SOLIDUS
    '\u{FF0F}', // FULLWIDTH SOLIDUS
    '\u{FF3C}', // FULLWIDTH REVERSE SOLIDUS
    '\u{2024}', // ONE DOT LEADER
    '\u{FF0E}', // FULLWIDTH FULL STOP
    '\u{FE52}', // SMALL FULL STOP
];

/// Why a piece of text was rejected before any filesystem lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextIssue {
    Empty,
    Nul,
    Control(char),
    Invisible(char),
    Lookalike(char),
}

impl std::fmt::Display for TextIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextIssue::Empty => write!(f, "empty path"),
            TextIssue::Nul => write!(f, "contains a NUL byte"),
            TextIssue::Control(c) => write!(f, "contains control character U+{:04X}", *c as u32),
            TextIssue::Invisible(c) => {
                write!(
                    f,
                    "contains invisible or bidi character U+{:04X}",
                    *c as u32
                )
            }
            TextIssue::Lookalike(c) => write!(
                f,
                "contains separator lookalike character U+{:04X}",
                *c as u32
            ),
        }
    }
}

/// True for bidi controls, zero-width characters, and other format characters that make a
/// string display differently from what the kernel sees.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{00AD}'
        | '\u{180E}')
}

/// Checks any argument for characters that hide intent (NUL, control, invisible, bidi).
pub fn check_arg_text(text: &str) -> Result<(), TextIssue> {
    for c in text.chars() {
        if c == '\0' {
            return Err(TextIssue::Nul);
        }
        if c.is_control() && c != '\t' && c != '\n' {
            return Err(TextIssue::Control(c));
        }
        if is_invisible(c) {
            return Err(TextIssue::Invisible(c));
        }
    }
    Ok(())
}

/// Checks text that will be used as a path. Stricter than [`check_arg_text`]: newlines,
/// tabs, and separator lookalikes are also rejected.
pub fn check_path_text(text: &str) -> Result<(), TextIssue> {
    if text.is_empty() {
        return Err(TextIssue::Empty);
    }
    for c in text.chars() {
        if c == '\0' {
            return Err(TextIssue::Nul);
        }
        if c.is_control() {
            return Err(TextIssue::Control(c));
        }
        if is_invisible(c) {
            return Err(TextIssue::Invisible(c));
        }
        if LOOKALIKES.contains(&c) {
            return Err(TextIssue::Lookalike(c));
        }
    }
    Ok(())
}

/// True if the text contains a separator lookalike.
pub fn has_lookalike(text: &str) -> bool {
    text.chars().any(|c| LOOKALIKES.contains(&c))
}

/// Values substituted into policy paths and environment values.
#[derive(Debug, Clone)]
pub struct Placeholders {
    pub workspace: PathBuf,
    pub home: Option<PathBuf>,
    pub scratch: Option<PathBuf>,
}

impl Placeholders {
    /// Expands `~`, `~/...`, `{home}`, `{workspace}`, and `{scratch}`. Relative results are
    /// joined onto the workspace.
    pub fn expand_path(&self, raw: &str) -> PathBuf {
        let text = self.expand_text(raw);
        let path = expand_tilde(&text, self.home.as_deref());
        if path.is_absolute() {
            path
        } else {
            self.workspace.join(path)
        }
    }

    /// Expands the brace placeholders in arbitrary text (used for environment values).
    pub fn expand_text(&self, raw: &str) -> String {
        let mut text = raw.replace("{workspace}", &self.workspace.to_string_lossy());
        if let Some(home) = &self.home {
            text = text.replace("{home}", &home.to_string_lossy());
        }
        if let Some(scratch) = &self.scratch {
            text = text.replace("{scratch}", &scratch.to_string_lossy());
        }
        text
    }
}

/// Expands a leading `~` or `~/` the way a shell would. `~user` is left untouched.
pub fn expand_tilde(text: &str, home: Option<&Path>) -> PathBuf {
    match home {
        Some(home) if text == "~" => home.to_path_buf(),
        Some(home) if text.starts_with("~/") => home.join(&text[2..]),
        _ => PathBuf::from(text),
    }
}

/// Resolves `path` (relative paths are joined onto `base`) to an absolute path with every
/// existing symlink followed and every `.` and `..` applied *after* symlink resolution, which
/// is how the kernel walks a path. Components that do not exist yet are appended lexically,
/// so the result names the location a write would create. Dangling symlinks are followed to
/// their target, so a link inside a writable directory cannot redirect a write elsewhere.
pub fn resolve(path: &Path, base: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut queue: VecDeque<OsString> = components(&absolute);
    let mut out = PathBuf::from("/");
    let mut followed = 0usize;
    while let Some(part) = queue.pop_front() {
        if part == ".." {
            out.pop();
            continue;
        }
        let candidate = out.join(&part);
        match std::fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => {
                followed += 1;
                if followed > MAX_SYMLINKS {
                    return Err(io::Error::other(format!(
                        "too many levels of symbolic links resolving {}",
                        absolute.display()
                    )));
                }
                let target = std::fs::read_link(&candidate)?;
                if target.is_absolute() {
                    out = PathBuf::from("/");
                }
                let mut next = components(&target);
                next.extend(queue);
                queue = next;
            }
            _ => out = candidate,
        }
    }
    Ok(out)
}

fn components(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// Component-wise containment: `/a/bc` is not within `/a/b`.
pub fn is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn canon(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap()
    }

    #[test]
    fn dotdot_is_applied_after_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(dir.path());
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir_all(root.join("x")).unwrap();
        symlink(root.join("a/b"), root.join("x/link")).unwrap();
        // x/link/.. is a/, not x/
        assert_eq!(
            resolve(Path::new("x/link/.."), &root).unwrap(),
            root.join("a")
        );
    }

    #[test]
    fn nonexistent_tail_is_lexical() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(dir.path());
        assert_eq!(
            resolve(Path::new("new/../file.txt"), &root).unwrap(),
            root.join("file.txt")
        );
        assert_eq!(
            resolve(&Path::new(&"../".repeat(40)).join("etc/passwd"), &root).unwrap(),
            canon(Path::new("/etc")).join("passwd")
        );
    }

    #[test]
    fn dangling_symlink_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(dir.path());
        symlink("/nonexistent-target/file", root.join("dangling")).unwrap();
        assert_eq!(
            resolve(Path::new("dangling"), &root).unwrap(),
            PathBuf::from("/nonexistent-target/file")
        );
    }

    #[test]
    fn symlink_loop_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(dir.path());
        symlink(root.join("b"), root.join("a")).unwrap();
        symlink(root.join("a"), root.join("b")).unwrap();
        assert!(resolve(Path::new("a"), &root).is_err());
    }

    #[test]
    fn relative_symlink_targets_resolve_from_link_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(dir.path());
        std::fs::create_dir_all(root.join("d")).unwrap();
        symlink("../target", root.join("d/rel")).unwrap();
        assert_eq!(
            resolve(Path::new("d/rel"), &root).unwrap(),
            root.join("target")
        );
    }

    #[test]
    fn text_checks() {
        assert_eq!(check_path_text(""), Err(TextIssue::Empty));
        assert_eq!(check_path_text("a\0b"), Err(TextIssue::Nul));
        assert!(matches!(
            check_path_text("a\nb"),
            Err(TextIssue::Control(_))
        ));
        assert!(matches!(
            check_path_text("..\u{2215}etc"),
            Err(TextIssue::Lookalike(_))
        ));
        assert!(matches!(
            check_path_text("file\u{202E}txt.sh"),
            Err(TextIssue::Invisible(_))
        ));
        assert!(check_path_text("caf\u{00e9}/notes.txt").is_ok());
        assert!(check_arg_text("hello\tworld\n").is_ok());
        assert!(check_arg_text("a\u{200B}b").is_err());
        assert!(check_arg_text("a\u{1b}[2J").is_err());
        assert!(has_lookalike("a\u{FF0F}b"));
        for issue in [
            TextIssue::Empty,
            TextIssue::Nul,
            TextIssue::Control('\u{1}'),
            TextIssue::Invisible('\u{200B}'),
            TextIssue::Lookalike('\u{2215}'),
        ] {
            assert!(!issue.to_string().is_empty());
        }
    }

    #[test]
    fn placeholders_expand() {
        let ph = Placeholders {
            workspace: PathBuf::from("/w"),
            home: Some(PathBuf::from("/h")),
            scratch: Some(PathBuf::from("/s")),
        };
        assert_eq!(ph.expand_path("~"), PathBuf::from("/h"));
        assert_eq!(ph.expand_path("~/.ssh"), PathBuf::from("/h/.ssh"));
        assert_eq!(ph.expand_path("{scratch}/x"), PathBuf::from("/s/x"));
        assert_eq!(ph.expand_path("rel"), PathBuf::from("/w/rel"));
        assert_eq!(ph.expand_path("~other"), PathBuf::from("/w/~other"));
        assert_eq!(ph.expand_text("{home}:{workspace}"), "/h:/w");
        assert!(is_within(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!is_within(Path::new("/a/bc"), Path::new("/a/b")));
    }
}
