//! Token-Optimized Object Notation writer.
//!
//! Goal: ~40% fewer tokens than JSON while staying unambiguous for LLMs.
//! Format:
//! ```text
//! key: value
//! list(3):
//!   col_a col_b col_c
//!   row1a row1b row1c
//!   row2a row2b row2c
//! nested:
//!   inner: 1
//! ```
//! Strings with whitespace, leading dashes, or special chars are double-quoted.

use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct Toon {
    buf: String,
    indent: usize,
}

impl Toon {
    pub fn new() -> Self {
        Self {
            buf: String::new(),
            indent: 0,
        }
    }

    pub fn into_string(self) -> String {
        self.buf
    }

    fn pad(&mut self) {
        for _ in 0..self.indent {
            self.buf.push_str("  ");
        }
    }

    pub fn field(&mut self, key: &str, val: impl ToonValue) -> &mut Self {
        self.pad();
        self.buf.push_str(key);
        self.buf.push_str(": ");
        val.write_to(&mut self.buf);
        self.buf.push('\n');
        self
    }

    /// One-off table that takes pre-formatted rows.
    pub fn table_strs(&mut self, key: &str, cols: &[&str], rows: &[Vec<String>]) -> &mut Self {
        self.pad();
        if rows.is_empty() {
            let _ = writeln!(self.buf, "{key}(0): empty");
            return self;
        }
        let _ = writeln!(self.buf, "{key}({}):", rows.len());
        self.indent += 1;
        self.pad();
        for (i, c) in cols.iter().enumerate() {
            if i > 0 {
                self.buf.push(' ');
            }
            escape_cell(c, &mut self.buf);
        }
        self.buf.push('\n');
        for r in rows {
            self.pad();
            for (i, cell) in r.iter().enumerate() {
                if i > 0 {
                    self.buf.push(' ');
                }
                escape_cell(cell, &mut self.buf);
            }
            self.buf.push('\n');
        }
        self.indent -= 1;
        self
    }

    /// Emit a `key: |` block followed by `content` indented by 2 spaces per
    /// line. Avoids the per-line `format!("  {line}")` allocation that the
    /// raw_line loop would do.
    pub fn block(&mut self, key: &str, content: &str) -> &mut Self {
        self.pad();
        self.buf.push_str(key);
        self.buf.push_str(": |\n");
        if content.is_empty() {
            return self;
        }
        let indent_pad = "  ".repeat(self.indent + 1);
        let mut start = 0usize;
        let bytes = content.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                self.buf.push_str(&indent_pad);
                self.buf.push_str(&content[start..i]);
                self.buf.push('\n');
                start = i + 1;
            }
        }
        if start < content.len() {
            self.buf.push_str(&indent_pad);
            self.buf.push_str(&content[start..]);
            self.buf.push('\n');
        }
        self
    }

    pub fn hint(&mut self, msg: &str) -> &mut Self {
        self.pad();
        self.buf.push_str("hint: ");
        self.buf.push_str(msg);
        self.buf.push('\n');
        self
    }
}

impl Default for Toon {
    fn default() -> Self {
        Self::new()
    }
}

pub trait ToonValue {
    fn write_to(&self, buf: &mut String);
}

impl ToonValue for &str {
    fn write_to(&self, buf: &mut String) {
        escape_scalar(self, buf);
    }
}
impl ToonValue for String {
    fn write_to(&self, buf: &mut String) {
        escape_scalar(self.as_str(), buf);
    }
}
impl ToonValue for &String {
    fn write_to(&self, buf: &mut String) {
        escape_scalar(self.as_str(), buf);
    }
}
impl ToonValue for u32 {
    fn write_to(&self, buf: &mut String) {
        let _ = write!(buf, "{self}");
    }
}
impl ToonValue for u64 {
    fn write_to(&self, buf: &mut String) {
        let _ = write!(buf, "{self}");
    }
}
impl ToonValue for i32 {
    fn write_to(&self, buf: &mut String) {
        let _ = write!(buf, "{self}");
    }
}
impl ToonValue for i64 {
    fn write_to(&self, buf: &mut String) {
        let _ = write!(buf, "{self}");
    }
}
impl ToonValue for usize {
    fn write_to(&self, buf: &mut String) {
        let _ = write!(buf, "{self}");
    }
}
impl ToonValue for bool {
    fn write_to(&self, buf: &mut String) {
        buf.push_str(if *self { "true" } else { "false" });
    }
}

fn escape_scalar(s: &str, buf: &mut String) {
    if !needs_quote(s) {
        buf.push_str(s);
        return;
    }
    buf.reserve(s.len() + 2);
    buf.push('"');
    // All escape targets (`"`, `\`, `\n`, `\r`, `\t`) are single-byte ASCII,
    // so bulk-copying the bytes between them never splits a UTF-8 codepoint.
    let bytes = s.as_bytes();
    let mut chunk_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            _ => continue,
        };
        buf.push_str(&s[chunk_start..i]);
        buf.push_str(esc);
        chunk_start = i + 1;
    }
    buf.push_str(&s[chunk_start..]);
    buf.push('"');
}

fn escape_cell(s: &str, buf: &mut String) {
    if s.is_empty() {
        buf.push_str("\"\"");
        return;
    }
    escape_scalar(s, buf);
}

fn needs_quote(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'-' {
        return true;
    }
    for &b in bytes {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\\' | b':' | b'#') {
            return true;
        }
    }
    matches!(s, "true" | "false" | "null")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields() {
        let mut t = Toon::new();
        t.field("name", "alice").field("age", 30u32);
        assert_eq!(t.into_string(), "name: alice\nage: 30\n");
    }

    #[test]
    fn quoting() {
        let mut t = Toon::new();
        t.field("greeting", "hello world");
        assert_eq!(t.into_string(), "greeting: \"hello world\"\n");
    }

    #[test]
    fn empty_table() {
        let mut t = Toon::new();
        let rows: Vec<Vec<String>> = vec![];
        t.table_strs("hosts", &["name"], &rows);
        assert_eq!(t.into_string(), "hosts(0): empty\n");
    }

    #[test]
    fn block_indents_each_line() {
        let mut t = Toon::new();
        t.block("stdout", "line1\nline2\nline3");
        let out = t.into_string();
        assert!(out.starts_with("stdout: |\n"));
        assert!(out.contains("  line1\n"));
        assert!(out.contains("  line2\n"));
        assert!(out.contains("  line3\n"));
    }

    #[test]
    fn block_handles_empty() {
        let mut t = Toon::new();
        t.block("stdout", "");
        assert_eq!(t.into_string(), "stdout: |\n");
    }

    #[test]
    fn table_with_rows() {
        let mut t = Toon::new();
        t.table_strs(
            "hosts",
            &["name", "addr", "port"],
            &[
                vec!["a".into(), "1.1.1.1".into(), "22".into()],
                vec!["b".into(), "2.2.2.2".into(), "2222".into()],
            ],
        );
        let out = t.into_string();
        assert!(out.contains("hosts(2):"));
        assert!(out.contains("name addr port"));
        assert!(out.contains("a 1.1.1.1 22"));
    }
}
