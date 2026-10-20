use std::borrow::Cow;
use std::fmt::Write;

/// Truncate long output keeping its start and its end, with a marker in the
/// middle saying how much was cut. On the common no-truncate path this borrows
/// the input, no copy. When truncated, returns the truncated `String` plus the
/// original total length so the caller can expose it in metadata.
pub fn truncate_with_hint(text: &str, max_bytes: usize) -> (Cow<'_, str>, Option<usize>) {
    head_tail(text, "", text.len(), max_bytes)
}

/// Fit a captured stream into `max_bytes` for display.
///
/// The stream is `head`, then `total - head.len() - tail.len()` bytes nobody
/// kept, then `tail`. The start and the end are what a reader needs: a build or
/// a log puts the command it ran at the top and the error at the bottom. When
/// the whole stream fits, and nothing was dropped between `head` and `tail`, it
/// comes back as is.
pub fn head_tail<'a>(
    head: &'a str,
    tail: &str,
    total: usize,
    max_bytes: usize,
) -> (Cow<'a, str>, Option<usize>) {
    let kept = head.len() + tail.len();
    let gap = total.saturating_sub(kept);
    if gap == 0 && kept <= max_bytes {
        if tail.is_empty() {
            return (Cow::Borrowed(head), None);
        }
        return (Cow::Owned(format!("{head}{tail}")), None);
    }

    let front = floor_boundary(head, (max_bytes / 2).min(head.len()));
    let mut back_budget = max_bytes - front;
    let from_tail = ceil_boundary(tail, tail.len().saturating_sub(back_budget));
    back_budget -= tail.len() - from_tail;
    // The end of `head` only continues into `tail` when nothing was dropped
    // between them. Otherwise it belongs before the gap, not after.
    let from_head = if gap == 0 && back_budget > 0 {
        ceil_boundary(head, head.len().saturating_sub(back_budget).max(front))
    } else {
        head.len()
    };

    let shown = front + (head.len() - from_head) + (tail.len() - from_tail);
    let cut = total.saturating_sub(shown);
    let mut out = String::with_capacity(shown + 80);
    out.push_str(&head[..front]);
    let _ = write!(
        out,
        "\n[{cut} of {total} bytes cut here; rerun through grep or tail to narrow]\n"
    );
    out.push_str(&head[from_head..]);
    out.push_str(&tail[from_tail..]);
    (Cow::Owned(out), Some(total))
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
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
    fn truncates_long_keeping_both_ends() {
        let s = format!("{}{}", "a".repeat(500), "z".repeat(500));
        let (out, n) = truncate_with_hint(&s, 50);
        assert!(out.starts_with(&"a".repeat(25)));
        assert!(out.ends_with(&"z".repeat(25)));
        assert!(out.contains("950 of 1000 bytes cut"));
        assert_eq!(n, Some(1000));
    }

    #[test]
    fn gap_between_head_and_tail_is_counted() {
        // 100 bytes kept at the start, 20 at the end, 880 never captured.
        let head = "h".repeat(100);
        let tail = "t".repeat(20);
        let (out, n) = head_tail(&head, &tail, 1000, 60);
        assert!(out.starts_with(&"h".repeat(30)));
        assert!(out.ends_with(&"t".repeat(20)));
        // Nothing from the end of `head` may follow the marker: those bytes
        // sit before the gap in the real stream.
        let after = out.split("narrow]\n").nth(1).unwrap();
        assert_eq!(after, "t".repeat(20));
        assert!(out.contains("950 of 1000 bytes cut"));
        assert_eq!(n, Some(1000));
    }

    #[test]
    fn contiguous_head_and_tail_that_fit_are_joined() {
        let (out, n) = head_tail("abc", "def", 6, 100);
        assert_eq!(out, "abcdef");
        assert_eq!(n, None);
    }

    #[test]
    fn small_capture_with_a_gap_still_reports_the_gap() {
        let (out, n) = head_tail("abc", "xyz", 1000, 100);
        assert!(out.starts_with("abc"));
        assert!(out.ends_with("xyz"));
        assert!(out.contains("994 of 1000 bytes cut"));
        assert_eq!(n, Some(1000));
    }

    #[test]
    fn cuts_on_char_boundaries() {
        let s = "é".repeat(100);
        let (out, _) = truncate_with_hint(&s, 21);
        let marker = out.find("\n[").unwrap();
        assert!(out[..marker].chars().all(|c| c == 'é'));
    }
}
