//! Minimal `ssh_config(5)` client-config parser.
//!
//! Exists instead of a crate because the obvious one (`ssh2-config-rs`) drags
//! the whole gitoxide stack (~45 `gix-*` crates) into the build to glob
//! `Include` paths. We use exactly one feature of it — importing plain host
//! aliases out of `~/.ssh/config` — so the dependency is replaced by this
//! file.
//!
//! Scope is deliberately narrow: `Host` blocks, keyword/value lines,
//! `Include`, and first-value-wins resolution. `Match` blocks are parsed only
//! so their keyword lines are not misattributed to the preceding `Host`
//! block; their conditions are never evaluated and their contents are
//! dropped. Token expansion (`%h`, `%p`, `%r`) is not performed, and no
//! value is interpreted beyond `Port` (parsed as `u16`).
//!
//! Everything here is fail-soft: a malformed line is skipped, a missing or
//! unreadable `Include` target is skipped (which is what OpenSSH does). Only
//! `parse_file` on the top-level path can fail, and it fails with the plain
//! `io::Error`. Nothing in this module can panic — the release profile is
//! `panic = "abort"`, so a panic here would take the MCP server down.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Include recursion cap. OpenSSH uses 16; 8 is more than any real config
/// needs and keeps a pathological tree cheap.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Safety valve for the include fan-out, so a directory of thousands of
/// globbed files can't stall startup.
const MAX_INCLUDE_FILES: usize = 256;

#[derive(Debug, Clone)]
struct Pattern {
    /// `!pattern` — a match here disqualifies the whole block.
    negated: bool,
    glob: String,
}

#[derive(Debug, Clone)]
struct Block {
    patterns: Vec<Pattern>,
    /// `(lowercased keyword, raw value)` in file order.
    entries: Vec<(String, String)>,
    /// Synthetic `Host *` block holding keywords that appear before the first
    /// `Host` line. Dropped when empty so it never shows up in resolution.
    implicit: bool,
}

impl Block {
    /// A block applies when at least one positive pattern matches and no
    /// negated pattern does.
    fn matches(&self, alias: &str) -> bool {
        let mut hit = false;
        for p in &self.patterns {
            if !glob_match(&p.glob, alias) {
                continue;
            }
            if p.negated {
                return false;
            }
            hit = true;
        }
        hit
    }
}

/// Parsed config: an ordered list of `Host` blocks.
#[derive(Debug, Default, Clone)]
pub struct SshConfig {
    blocks: Vec<Block>,
}

/// Result of resolving one alias against every matching block.
#[derive(Debug, Default, Clone)]
pub struct ResolvedHost {
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Every `IdentityFile` seen across all matching blocks, in file order.
    /// Not deduplicated and not path-expanded — `~` is left as written.
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
}

impl SshConfig {
    /// Parses `path`, resolving `Include` directives relative to the
    /// containing file's directory and to `~/.ssh/`. Only the top-level read
    /// can fail; included files that are missing or unreadable are skipped.
    pub fn parse_file(path: &Path) -> std::io::Result<SshConfig> {
        let text = std::fs::read_to_string(path)?;
        let mut p = Parser::new(true);
        p.mark_visited(path);
        let dir = path.parent().map(|d| d.to_path_buf());
        p.feed(&text, dir.as_deref(), 0);
        Ok(p.finish())
    }

    /// Parses config text with no filesystem access at all: `Include` lines
    /// are recognized and discarded rather than resolved.
    #[allow(dead_code)] // used by the tests; production path goes through parse_file.
    pub fn parse_str(s: &str) -> SshConfig {
        let mut p = Parser::new(false);
        p.feed(s, None, 0);
        p.finish()
    }

    /// Walks blocks in file order and keeps the **first** value seen for each
    /// keyword, which is the real OpenSSH rule — a `Host *` block at the
    /// bottom therefore acts as defaults. `IdentityFile` accumulates instead
    /// of being overwritten.
    pub fn query(&self, alias: &str) -> ResolvedHost {
        let mut out = ResolvedHost::default();
        let mut seen: HashSet<&str> = HashSet::new();
        for b in &self.blocks {
            if !b.matches(alias) {
                continue;
            }
            for (k, v) in &b.entries {
                if k == "identityfile" {
                    out.identity_files.push(v.clone());
                    continue;
                }
                if !seen.insert(k.as_str()) {
                    continue;
                }
                match k.as_str() {
                    "hostname" => out.host_name = Some(v.clone()),
                    "user" => out.user = Some(v.clone()),
                    "port" => out.port = v.parse().ok(),
                    "proxyjump" => out.proxy_jump = Some(v.clone()),
                    _ => {}
                }
            }
        }
        out
    }

    /// Every literal alias declared by a `Host` line, in file order, deduped.
    /// Wildcard (`*`, `?`) and negated patterns are skipped — they name a
    /// class of hosts, not a host.
    pub fn list_aliases(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for b in &self.blocks {
            for p in &b.patterns {
                if p.negated || p.glob.contains('*') || p.glob.contains('?') {
                    continue;
                }
                if seen.insert(p.glob.as_str()) {
                    out.push(p.glob.clone());
                }
            }
        }
        out
    }
}

struct Parser {
    blocks: Vec<Block>,
    current: Option<Block>,
    /// Whether `Include` is followed. `parse_str` never touches the disk.
    resolve_includes: bool,
    /// Canonicalized paths already fed, so an include cycle terminates.
    visited: HashSet<PathBuf>,
    included: usize,
}

impl Parser {
    fn new(resolve_includes: bool) -> Self {
        Self {
            blocks: Vec::new(),
            // Keywords before the first `Host` line are global defaults in
            // OpenSSH, i.e. an implicit `Host *` at the very top.
            current: Some(Block {
                patterns: vec![Pattern {
                    negated: false,
                    glob: "*".to_string(),
                }],
                entries: Vec::new(),
                implicit: true,
            }),
            resolve_includes,
            visited: HashSet::new(),
            included: 0,
        }
    }

    fn mark_visited(&mut self, path: &Path) {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.visited.insert(canon);
    }

    fn flush(&mut self) {
        if let Some(b) = self.current.take() {
            if b.implicit && b.entries.is_empty() {
                return;
            }
            self.blocks.push(b);
        }
    }

    fn finish(mut self) -> SshConfig {
        self.flush();
        SshConfig {
            blocks: self.blocks,
        }
    }

    fn feed(&mut self, text: &str, base_dir: Option<&Path>, depth: usize) {
        for raw in text.lines() {
            let line = strip_comment(raw);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((kw, value)) = split_kv(line) else {
                continue;
            };
            if kw.eq_ignore_ascii_case("host") {
                self.flush();
                self.current = Some(Block {
                    patterns: parse_patterns(&value),
                    entries: Vec::new(),
                    implicit: false,
                });
                continue;
            }
            if kw.eq_ignore_ascii_case("match") {
                // Parsed only to stop the following keywords from landing in
                // the previous Host block. Conditions are never evaluated.
                self.flush();
                self.current = None;
                continue;
            }
            if kw.eq_ignore_ascii_case("include") {
                if self.resolve_includes {
                    self.include(&value, base_dir, depth);
                }
                continue;
            }
            if value.is_empty() {
                continue;
            }
            if let Some(b) = self.current.as_mut() {
                b.entries.push((kw.to_ascii_lowercase(), unquote(&value)));
            }
        }
    }

    fn include(&mut self, value: &str, base_dir: Option<&Path>, depth: usize) {
        if depth >= MAX_INCLUDE_DEPTH {
            return;
        }
        for tok in split_tokens(value) {
            for path in resolve_include(&tok, base_dir) {
                if self.included >= MAX_INCLUDE_FILES {
                    return;
                }
                let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                if !self.visited.insert(canon) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                self.included += 1;
                let dir = path.parent().map(|d| d.to_path_buf());
                // Included content is spliced in at this point, so it keeps
                // extending whatever Host block is currently open.
                self.feed(&text, dir.as_deref(), depth + 1);
            }
        }
    }
}

/// Splits `Host a b !c` into its patterns.
fn parse_patterns(value: &str) -> Vec<Pattern> {
    split_tokens(value)
        .into_iter()
        .filter_map(|t| {
            let (negated, glob) = match t.strip_prefix('!') {
                Some(rest) => (true, rest.to_string()),
                None => (false, t),
            };
            if glob.is_empty() {
                None
            } else {
                Some(Pattern { negated, glob })
            }
        })
        .collect()
}

/// Cuts a trailing `#` comment when it sits outside double quotes. OpenSSH
/// itself only honors whole-line comments; trailing ones are accepted here
/// because every hand-written config uses them.
fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            '#' if !in_quote => return line.get(..i).unwrap_or(""),
            _ => {}
        }
    }
    line
}

/// Splits `Keyword value...` on whitespace or `=` (`Port=2222` is valid).
/// Returns `None` only for an empty line.
fn split_kv(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    for (i, c) in line.char_indices() {
        if c.is_whitespace() || c == '=' {
            let kw = line.get(..i)?.to_string();
            let rest = line.get(i..)?.trim_start();
            let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
            return Some((kw, rest.trim_end().to_string()));
        }
    }
    // Bare keyword with no value.
    Some((line.to_string(), String::new()))
}

/// Whitespace-separated tokens, honoring double quotes.
fn split_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_quote = false;
    for c in s.chars() {
        if in_quote {
            if c == '"' {
                in_quote = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '"' => {
                in_quote = true;
                quoted = true;
            }
            c if c.is_whitespace() => {
                if quoted || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    quoted = false;
                }
            }
            _ => cur.push(c),
        }
    }
    if quoted || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Strips one pair of surrounding double quotes, if present.
fn unquote(v: &str) -> String {
    let t = v.trim();
    match t.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        Some(inner) => inner.to_string(),
        None => t.to_string(),
    }
}

fn expand_tilde(s: &str) -> PathBuf {
    if s == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    for prefix in ["~/", "~\\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
    }
    PathBuf::from(s)
}

/// Resolves one `Include` token to concrete files: absolute as written,
/// relative against the containing file's directory then against `~/.ssh/`,
/// with `*`/`?` globbing on the final path component only.
fn resolve_include(tok: &str, base_dir: Option<&Path>) -> Vec<PathBuf> {
    let expanded = expand_tilde(tok);
    let mut candidates: Vec<PathBuf> = Vec::new();
    if expanded.is_absolute() {
        candidates.push(expanded);
    } else {
        if let Some(d) = base_dir {
            candidates.push(d.join(&expanded));
        }
        if let Some(h) = dirs::home_dir() {
            candidates.push(h.join(".ssh").join(&expanded));
        }
    }
    let mut out = Vec::new();
    for c in candidates {
        out.extend(expand_glob(&c));
    }
    out
}

/// Expands `*`/`?` in the final component of `p`. Anything else is returned
/// as-is when it exists as a file.
fn expand_glob(p: &Path) -> Vec<PathBuf> {
    let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    if !name.contains('*') && !name.contains('?') {
        return if p.is_file() {
            vec![p.to_path_buf()]
        } else {
            Vec::new()
        };
    }
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in rd.flatten() {
        let fname = entry.file_name();
        let Some(f) = fname.to_str() else { continue };
        // Dotfiles never match a glob, same as a shell.
        if f.starts_with('.') {
            continue;
        }
        if !glob_match(name, f) {
            continue;
        }
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        }
    }
    // read_dir order is filesystem-dependent; sort so includes are stable.
    out.sort();
    out
}

/// `*` matches any run of characters, `?` exactly one. Iterative with a
/// single backtrack point, so it is linear in practice and cannot recurse
/// itself into a stack overflow. Compares by `char`, never by byte offset.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while ti < t.len() {
        match (p.get(pi), t.get(ti)) {
            (Some('*'), _) => {
                star = Some(pi);
                resume = ti;
                pi += 1;
            }
            (Some('?'), Some(_)) => {
                pi += 1;
                ti += 1;
            }
            (Some(pc), Some(tc)) if pc == tc => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    resume += 1;
                    ti = resume;
                }
                None => return false,
            },
        }
    }
    while matches!(p.get(pi), Some('*')) {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_host_block() {
        let c = SshConfig::parse_str("Host web\n  HostName 10.0.0.1\n  User deploy\n  Port 2200\n");
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.user.as_deref(), Some("deploy"));
        assert_eq!(r.port, Some(2200));
        assert!(r.identity_files.is_empty());
        assert!(r.proxy_jump.is_none());
    }

    #[test]
    fn equals_separator() {
        let c = SshConfig::parse_str("Host=web\nHostName=10.0.0.1\nPort=2222\nUser = bob\n");
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.port, Some(2222));
        assert_eq!(r.user.as_deref(), Some("bob"));
    }

    #[test]
    fn quoted_value_is_unquoted() {
        let c = SshConfig::parse_str(
            "Host web\n  HostName \"10.0.0.1\"\n  IdentityFile \"/home/a b/id_ed25519\"\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.identity_files, vec!["/home/a b/id_ed25519".to_string()]);
    }

    #[test]
    fn keywords_are_case_insensitive_values_are_not() {
        let c = SshConfig::parse_str("HOST web\n  hostname Server.EXAMPLE.com\n  UsEr Bob\n");
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("Server.EXAMPLE.com"));
        assert_eq!(r.user.as_deref(), Some("Bob"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let c = SshConfig::parse_str(
            "# leading comment\n\n\
             Host web\n\
             \t# indented comment\n\
             \tHostName 10.0.0.1  # trailing comment\n\
             \n\
             \tUser deploy\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn multiple_patterns_on_one_host_line() {
        let c = SshConfig::parse_str("Host alpha beta gamma\n  User shared\n");
        for a in ["alpha", "beta", "gamma"] {
            assert_eq!(c.query(a).user.as_deref(), Some("shared"), "alias {a}");
        }
        assert!(c.query("delta").user.is_none());
        assert_eq!(c.list_aliases(), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn star_wildcard_pattern() {
        let c = SshConfig::parse_str("Host prod-*\n  User ops\n");
        assert_eq!(c.query("prod-web").user.as_deref(), Some("ops"));
        assert_eq!(c.query("prod-").user.as_deref(), Some("ops"));
        assert!(c.query("staging-web").user.is_none());
    }

    #[test]
    fn question_mark_matches_exactly_one_char() {
        let c = SshConfig::parse_str("Host node?\n  User n\n");
        assert_eq!(c.query("node1").user.as_deref(), Some("n"));
        assert!(c.query("node").user.is_none());
        assert!(c.query("node12").user.is_none());
    }

    #[test]
    fn negated_pattern_disqualifies_block() {
        let c = SshConfig::parse_str("Host *.internal !secret.internal\n  User ops\n");
        assert_eq!(c.query("db.internal").user.as_deref(), Some("ops"));
        assert!(c.query("secret.internal").user.is_none());
    }

    #[test]
    fn first_value_wins_across_two_matching_blocks() {
        let c = SshConfig::parse_str(
            "Host web\n  HostName first.example\n  Port 2200\n\
             Host web\n  HostName second.example\n  Port 2300\n  User late\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("first.example"));
        assert_eq!(r.port, Some(2200));
        // A keyword absent from the earlier block still comes from the later one.
        assert_eq!(r.user.as_deref(), Some("late"));
    }

    #[test]
    fn host_star_acts_as_defaults() {
        let c = SshConfig::parse_str(
            "Host web\n  HostName 10.0.0.1\n\
             Host *\n  User fallback\n  Port 2222\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.user.as_deref(), Some("fallback"));
        assert_eq!(r.port, Some(2222));
        // The defaults block alone still resolves for an unknown alias.
        let other = c.query("whatever");
        assert_eq!(other.user.as_deref(), Some("fallback"));
        assert!(other.host_name.is_none());
    }

    #[test]
    fn identity_files_accumulate_in_order() {
        let c = SshConfig::parse_str(
            "Host web\n  IdentityFile ~/.ssh/id_ed25519\n  IdentityFile ~/.ssh/id_rsa\n\
             Host *\n  IdentityFile ~/.ssh/id_default\n",
        );
        assert_eq!(
            c.query("web").identity_files,
            vec![
                "~/.ssh/id_ed25519".to_string(),
                "~/.ssh/id_rsa".to_string(),
                "~/.ssh/id_default".to_string(),
            ]
        );
    }

    #[test]
    fn match_block_does_not_leak_into_previous_host() {
        let c = SshConfig::parse_str(
            "Host web\n  HostName 10.0.0.1\n\
             Match host bastion\n  User matched\n  Port 9999\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert!(
            r.user.is_none(),
            "Match keywords must not reach the Host block"
        );
        assert!(r.port.is_none());
        // And the Match block itself is never applied to anything.
        assert!(c.query("bastion").user.is_none());
    }

    #[test]
    fn host_after_match_starts_a_fresh_block() {
        let c = SshConfig::parse_str(
            "Match exec true\n  User matched\n\
             Host web\n  HostName 10.0.0.1\n",
        );
        let r = c.query("web");
        assert_eq!(r.host_name.as_deref(), Some("10.0.0.1"));
        assert!(r.user.is_none());
        assert_eq!(c.list_aliases(), vec!["web"]);
    }

    #[test]
    fn list_aliases_skips_wildcards_and_negations_and_dedupes() {
        let c = SshConfig::parse_str(
            "Host web db\n  User a\n\
             Host *\n  User b\n\
             Host node? !nope other\n  User c\n\
             Host web\n  Port 22\n",
        );
        assert_eq!(c.list_aliases(), vec!["web", "db", "other"]);
    }

    #[test]
    fn proxy_jump_is_read() {
        let c = SshConfig::parse_str("Host web\n  ProxyJump bastion\n  HostName 10.0.0.1\n");
        assert_eq!(c.query("web").proxy_jump.as_deref(), Some("bastion"));
    }

    #[test]
    fn keywords_before_first_host_are_global_defaults() {
        let c = SshConfig::parse_str("User global\nHost web\n  HostName 10.0.0.1\n  User local\n");
        // Global block comes first in file order, so first-wins picks it.
        assert_eq!(c.query("web").user.as_deref(), Some("global"));
        assert_eq!(c.query("anything").user.as_deref(), Some("global"));
        assert_eq!(c.list_aliases(), vec!["web"]);
    }

    #[test]
    fn unparseable_and_empty_values_are_skipped() {
        let c = SshConfig::parse_str("Host web\n  Port notanumber\n  HostName\n  User bob\n");
        let r = c.query("web");
        assert_eq!(r.port, None);
        assert_eq!(r.host_name, None);
        assert_eq!(r.user.as_deref(), Some("bob"));
    }

    #[test]
    fn include_is_ignored_by_parse_str() {
        let c =
            SshConfig::parse_str("Host web\n  Include /nonexistent/*.conf\n  HostName 10.0.0.1\n");
        assert_eq!(c.query("web").host_name.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn glob_match_edges() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(glob_match("*.example.com", "host.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("é?é", "éxé"));
        assert!(!glob_match("abc", "abcd"));
        assert!(!glob_match("abcd", "abc"));
    }

    #[test]
    fn no_match_returns_empty_resolution() {
        let c = SshConfig::parse_str("Host web\n  HostName 10.0.0.1\n");
        let r = c.query("nothing");
        assert!(r.host_name.is_none());
        assert!(r.user.is_none());
        assert!(r.port.is_none());
        assert!(r.identity_files.is_empty());
        assert!(r.proxy_jump.is_none());
    }
}
