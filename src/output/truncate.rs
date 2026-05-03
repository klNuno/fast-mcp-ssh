/// Truncate long output keeping a head + a short hint about how much was cut.
/// Returns trimmed text. Caller may also expose `truncated_bytes` in metadata.
pub fn truncate_with_hint(text: &str, max_bytes: usize) -> (String, Option<usize>) {
    if text.len() <= max_bytes {
        return (text.to_string(), None);
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let total = text.len();
    let mut out = String::with_capacity(cut + 32);
    out.push_str(&text[..cut]);
    out.push_str(&format!("\n…[+{}B truncated]", total - cut));
    (out, Some(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_truncate_under_limit() {
        let (out, n) = truncate_with_hint("short", 100);
        assert_eq!(out, "short");
        assert_eq!(n, None);
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
