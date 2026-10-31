//! Table and JSON output.

use std::io::Write;

use serde::Serialize;
use serde_json::Value;

/// How a cell is computed from a JSON item.
pub type Cell = Box<dyn Fn(&Value) -> String>;

/// A table column: header and cell function.
pub struct Col {
    pub header: &'static str,
    pub cell: Cell,
}

/// Column reading a JSON pointer (`/decision/rule_name`).
pub fn col(header: &'static str, pointer: &'static str) -> Col {
    Col {
        header,
        cell: Box::new(move |v| scalar(v.pointer(pointer))),
    }
}

/// Column computed by a function.
pub fn colf(header: &'static str, f: impl Fn(&Value) -> String + 'static) -> Col {
    Col {
        header,
        cell: Box::new(f),
    }
}

/// Renders a JSON scalar (or a short list) for a table cell.
pub fn scalar(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => if *b { "yes" } else { "no" }.into(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Array(a)) if a.is_empty() => "-".into(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| scalar(Some(x)))
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(o)) => o
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| Value::Object(o.clone()).to_string()),
    }
}

/// Formats an RFC 3339 timestamp as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn time_cell(v: Option<&Value>) -> String {
    match v.and_then(Value::as_str) {
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| {
                t.with_timezone(&chrono::Utc)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            })
            .unwrap_or_else(|_| s.to_string()),
        None => "-".into(),
    }
}

/// Writes a table (headers in upper case, columns separated by two spaces).
pub fn table(out: &mut dyn Write, items: &[Value], cols: &[Col]) -> std::io::Result<()> {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|it| {
            cols.iter()
                .map(|c| sanitize(&(c.cell)(it)))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut widths: Vec<usize> = cols.iter().map(|c| c.header.chars().count()).collect();
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c.to_string()
                } else {
                    format!("{c:<w$}", w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    writeln!(out, "{}", line(cols.iter().map(|c| c.header).collect()))?;
    for r in &rows {
        writeln!(out, "{}", line(r.iter().map(String::as_str).collect()))?;
    }
    Ok(())
}

/// Removes control characters (API data is untrusted: no terminal escapes).
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Pretty JSON.
pub fn json(out: &mut dyn Write, v: &impl Serialize) -> std::io::Result<()> {
    let s = serde_json::to_string_pretty(v).map_err(std::io::Error::other)?;
    writeln!(out, "{s}")
}

/// `key: value` lines for a flat summary.
pub fn kv(out: &mut dyn Write, pairs: &[(&str, String)]) -> std::io::Result<()> {
    let w = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in pairs {
        writeln!(out, "{:<w$}  {}", format!("{k}:"), sanitize(v), w = w + 1)?;
    }
    Ok(())
}
