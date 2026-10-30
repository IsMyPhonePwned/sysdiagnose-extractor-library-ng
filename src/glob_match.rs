// SPDX-License-Identifier: GPL-3.0-only

//! SAF-style globs: `/` separates segments, `*` does not cross `/`,
//! `**` matches any number of segments including zero.

pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    rec(&pat, &segs)
}

fn rec(pat: &[&str], segs: &[&str]) -> bool {
    if pat.is_empty() {
        return segs.is_empty();
    }
    if pat[0] == "**" {
        if rec(&pat[1..], segs) {
            return true;
        }
        return !segs.is_empty() && rec(pat, &segs[1..]);
    }
    if segs.is_empty() {
        return false;
    }
    seg_match(pat[0], segs[0]) && rec(&pat[1..], &segs[1..])
}

fn seg_match(pat: &str, seg: &str) -> bool {
    bytes_match(pat.as_bytes(), seg.as_bytes())
}

fn bytes_match(pat: &[u8], seg: &[u8]) -> bool {
    if pat.is_empty() {
        return seg.is_empty();
    }
    if pat[0] == b'*' {
        return bytes_match(&pat[1..], seg) || (!seg.is_empty() && bytes_match(pat, &seg[1..]));
    }
    if seg.is_empty() {
        return false;
    }
    (pat[0] == b'?' || pat[0] == seg[0]) && bytes_match(&pat[1..], &seg[1..])
}

pub fn any_glob(patterns: &[&str], path: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_does_not_cross_slash() {
        assert!(glob_match("*.txt", "ok.txt"));
        assert!(!glob_match("*.txt", "a/ok.txt"));
        assert!(glob_match("**/*.txt", "ok.txt"));
        assert!(glob_match("**/*.txt", "a/b/ok.txt"));
        assert!(glob_match("**/x.txt", "x.txt"));
        assert!(glob_match("logs/MobileLockdown/lockdownd.log*", "logs/MobileLockdown/lockdownd.log.0"));
    }
}
