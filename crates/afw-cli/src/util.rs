//! Small parsing helpers.

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Duration, Utc};

/// `15m`, `2h`, `7d`, `30s`, `2w` → duration.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    match unit {
        "s" => Duration::try_seconds(n),
        "m" => Duration::try_minutes(n),
        "h" => Duration::try_hours(n),
        "d" => Duration::try_days(n),
        "w" => Duration::try_weeks(n),
        _ => None,
    }
}

/// RFC 3339 time, or a duration ago (`2h` = two hours ago).
pub fn parse_past(s: &str) -> Result<DateTime<Utc>> {
    parse_time(s, -1)
}

/// RFC 3339 time, or a duration from now (`7d` = in seven days).
pub fn parse_future(s: &str) -> Result<DateTime<Utc>> {
    parse_time(s, 1)
}

fn parse_time(s: &str, sign: i32) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    if let Some(d) = parse_duration(s) {
        return Ok(if sign < 0 {
            Utc::now() - d
        } else {
            Utc::now() + d
        });
    }
    Err(anyhow!(
        "invalid time `{s}`: expected RFC 3339 (2026-10-30T08:00:00Z) or a duration (15m, 2h, 7d)"
    ))
}

pub fn opt_past(s: &Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.as_deref().map(parse_past).transpose()
}

/// `KEY=VALUE` pair.
pub fn key_value(s: &str) -> Result<(String, String)> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => bail!("expected KEY=VALUE, got `{s}`"),
    }
}

/// JSON enum value from a CLI word (`self-test` → `self_test`).
pub fn enum_word(s: &str) -> String {
    s.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_times() {
        assert_eq!(parse_duration("15m"), Some(Duration::minutes(15)));
        assert_eq!(parse_duration("7d"), Some(Duration::days(7)));
        assert_eq!(parse_duration("7"), None);
        assert_eq!(parse_duration("x"), None);
        let t = parse_past("2026-10-30T08:00:00Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-30T08:00:00+00:00");
        let ago = parse_past("1h").unwrap();
        assert!(ago < Utc::now() && ago > Utc::now() - Duration::minutes(61));
        assert!(parse_future("1d").unwrap() > Utc::now());
        assert!(parse_past("yesterday").is_err());
    }
}
