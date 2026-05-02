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
        Self { buf: String::new(), indent: 0 }
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

    pub fn raw_line(&mut self, s: &str) -> &mut Self {
        self.pad();
        self.buf.push_str(s);
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
        self.buf.push_str(&cols.join(" "));
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

    pub fn hint(&mut self, msg: &str) -> &mut Self {
        self.pad();
        self.buf.push_str("hint: ");
        self.buf.push_str(msg);
        self.buf.push('\n');
        self
    }
}

impl Default for Toon {
    fn default() -> Self { Self::new() }
}

pub trait ToonValue {
    fn write_to(&self, buf: &mut String);
}

impl ToonValue for &str {
    fn write_to(&self, buf: &mut String) { escape_scalar(self, buf); }
}
impl ToonValue for String {
    fn write_to(&self, buf: &mut String) { escape_scalar(self.as_str(), buf); }
}
impl ToonValue for &String {
    fn write_to(&self, buf: &mut String) { escape_scalar(self.as_str(), buf); }
}
impl ToonValue for u16 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for u32 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for u64 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for i32 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for i64 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for usize { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }
impl ToonValue for bool { fn write_to(&self, buf: &mut String) { buf.push_str(if *self { "true" } else { "false" }); } }
impl ToonValue for f64 { fn write_to(&self, buf: &mut String) { let _ = write!(buf, "{self}"); } }

fn escape_scalar(s: &str, buf: &mut String) {
    if needs_quote(s) {
        buf.push('"');
        for c in s.chars() {
            match c {
                '"' => buf.push_str("\\\""),
                '\\' => buf.push_str("\\\\"),
                '\n' => buf.push_str("\\n"),
                '\r' => buf.push_str("\\r"),
                '\t' => buf.push_str("\\t"),
                _ => buf.push(c),
            }
        }
        buf.push('"');
    } else {
        buf.push_str(s);
    }
}

fn escape_cell(s: &str, buf: &mut String) {
    if s.is_empty() {
        buf.push_str("\"\"");
        return;
    }
    escape_scalar(s, buf);
}

fn needs_quote(s: &str) -> bool {
    if s.is_empty() { return true; }
    s.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"' | '\\' | ':' | '#'))
        || s.starts_with('-')
        || s == "true" || s == "false" || s == "null"
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
