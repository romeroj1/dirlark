//! Public compile-time identity only; no runtime environment or machine details.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildInfo<'a> {
    pub version: &'a str,
    pub commit: &'a str,
    pub built: &'a str,
}
impl<'a> BuildInfo<'a> {
    pub fn from_values(version: &'a str, commit: &'a str, built: &'a str) -> Self {
        let version = if !version.is_empty()
            && version.len() <= 64
            && version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
        {
            version
        } else {
            "dev"
        };
        let commit = if commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            commit
        } else {
            "dev"
        };
        // Build tooling emits UTC RFC3339. Restrict display/log metadata to that
        // bounded ASCII shape; no arbitrary environment values enter the UI.
        let built = if utc_timestamp(built) { built } else { "dev" };
        Self {
            version,
            commit,
            built,
        }
    }
    pub fn text(&self) -> String {
        format!(
            "DIRLARK {}\nCommit: {}\nBuilt (UTC): {}\nLicence: Apache-2.0\nSource: https://github.com/romeroj1/dirlark",
            self.version, self.commit, self.built
        )
    }
}
pub fn current() -> BuildInfo<'static> {
    BuildInfo::from_values(
        option_env!("DIRLARK_BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
        option_env!("DIRLARK_BUILD_COMMIT").unwrap_or("dev"),
        option_env!("DIRLARK_BUILD_DATE").unwrap_or("dev"),
    )
}
fn utc_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, v)| ![4, 7, 10, 13, 16, 19].contains(&i) && !v.is_ascii_digit())
    {
        return false;
    }
    let number = |a, z| s[a..z].parse::<u32>().unwrap_or(0);
    let year = number(0, 4);
    let month = number(5, 7);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0
        && number(8, 10) > 0
        && number(8, 10) <= days
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_metadata_accepts_alpha_and_safe_defaults() {
        let b = BuildInfo::from_values(
            "0.1.0-alpha.1",
            "0123456789abcdef0123456789abcdef01234567",
            "2026-10-19T12:34:56Z",
        );
        assert_eq!(b.version, "0.1.0-alpha.1");
        assert!(b.text().contains(b.commit));
        assert_eq!(
            BuildInfo::from_values("bad\nmetadata", "unknown", "yesterday"),
            BuildInfo {
                version: "dev",
                commit: "dev",
                built: "dev"
            }
        );
        assert_eq!(
            BuildInfo::from_values(&"x".repeat(65), "", "2026-02-30T00:00:00Z").built,
            "dev"
        );
        assert!(utc_timestamp("2028-02-29T00:00:00Z"));
        for bad in [
            "2026-02-29T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:60:00Z",
            "é026-01-01T00:00:00Z",
        ] {
            assert!(!utc_timestamp(bad));
        }
    }
}
