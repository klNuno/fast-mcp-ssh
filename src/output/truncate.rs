use std::borrow::Cow;
use std::fmt::Write;

/// Truncate long output keeping a head + a short hint about how much was cut.
/// On the common no-truncate path this borrows the input — no copy. When
/// truncated, returns the truncated `String` plus the original total length so
/// the caller can expose it in metadata.
pub fn truncate_with_hint(text: &str, max_bytes: usize) -> (Cow<'_, str>, Option<usize>) {
    if text.len() <= max_bytes {
        return (Cow::Borrowed(text), None);
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let total = text.len();
    let mut out = String::with_capacity(cut + 32);
    out.push_str(&text[..cut]);
    let _ = write!(out, "\n…[+{}B truncated]", total - cut);
    (Cow::Owned(out), Some(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_truncate_under_limit() {
        let (out, n) = truncate_with_hint("short", 100);
        assert_eq!(out, "short");
        assert_eq!(n, None);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn truncates_long() {
        let s = "a".repeat(1000);
        let (out, n) = truncate_with_hint(&s, 50);
        assert!(out.starts_with(&"a".repeat(50)));
        assert!(out.contains("truncated"));
        assert_eq!(n, Some(1000));
    }
}
