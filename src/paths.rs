//! Paths into a JSON response: `images[].url`, `connection_uris[0].connection_uri`,
//! `data.variables.*`. Dots descend into objects; `key[]` fans out over an array,
//! `key[N]` picks one item, and `*` fans out over every value of an object (or
//! every item of an array).

use serde_json::Value;

#[derive(Clone, Copy)]
enum Step<'a> {
    Key(&'a str),
    Each,
    Index(usize),
}

fn steps(path: &str) -> Vec<Step<'_>> {
    let mut out = Vec::new();
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        if seg == "*" {
            out.push(Step::Each);
            continue;
        }
        let (key, rest) = match seg.find('[') {
            Some(i) => (&seg[..i], &seg[i..]),
            None => (seg, ""),
        };
        if !key.is_empty() {
            out.push(Step::Key(key));
        }
        let mut rest = rest;
        while let Some(inner) = rest.strip_prefix('[') {
            let Some(close) = inner.find(']') else { break };
            match &inner[..close] {
                "" => out.push(Step::Each),
                n => match n.parse() {
                    Ok(i) => out.push(Step::Index(i)),
                    Err(_) => out.push(Step::Key(n)),
                },
            }
            rest = &inner[close + 1..];
        }
    }
    out
}

/// Every value at `path`, with the concrete path that reached it
/// (`data.variables.DATABASE_URL`, `connection_uris[0].connection_uri`).
pub fn find<'a>(root: &'a Value, path: &str) -> Vec<(String, &'a Value)> {
    let mut current = vec![(String::new(), root)];
    for step in steps(path) {
        let mut next = Vec::new();
        for (at, value) in current {
            match (step, value) {
                (Step::Key(k), Value::Object(map)) => {
                    if let Some(v) = map.get(k) {
                        next.push((join(&at, k), v));
                    }
                }
                (Step::Each, Value::Array(items)) => {
                    next.extend(items.iter().enumerate().map(|(i, v)| (format!("{at}[{i}]"), v)));
                }
                (Step::Each, Value::Object(map)) => {
                    next.extend(map.iter().map(|(k, v)| (join(&at, k), v)));
                }
                (Step::Index(i), Value::Array(items)) => {
                    if let Some(v) = items.get(i) {
                        next.push((format!("{at}[{i}]"), v));
                    }
                }
                _ => {}
            }
        }
        current = next;
    }
    current
}

/// Replace every string at `path` using `f`.
pub fn replace_strings(root: &mut Value, path: &str, f: &dyn Fn(&str) -> String) {
    fn walk(value: &mut Value, steps: &[Step<'_>], f: &dyn Fn(&str) -> String) {
        let Some((step, rest)) = steps.split_first() else {
            if let Value::String(s) = value {
                *s = f(s);
            }
            return;
        };
        match (*step, value) {
            (Step::Key(k), Value::Object(map)) => {
                if let Some(v) = map.get_mut(k) {
                    walk(v, rest, f);
                }
            }
            (Step::Each, Value::Array(items)) => items.iter_mut().for_each(|v| walk(v, rest, f)),
            (Step::Each, Value::Object(map)) => map.values_mut().for_each(|v| walk(v, rest, f)),
            (Step::Index(i), Value::Array(items)) => {
                if let Some(v) = items.get_mut(i) {
                    walk(v, rest, f);
                }
            }
            _ => {}
        }
    }
    walk(root, &steps(path), f);
}

fn join(at: &str, key: &str) -> String {
    if at.is_empty() { key.to_string() } else { format!("{at}.{key}") }
}

/// Replace every occurrence of each `secret` inside any string in `root`.
pub fn redact(root: &mut Value, secrets: &[String], f: &dyn Fn(&str) -> String) {
    match root {
        Value::String(s) => *s = redact_text(s, secrets, f),
        Value::Array(items) => items.iter_mut().for_each(|v| redact(v, secrets, f)),
        Value::Object(map) => map.values_mut().for_each(|v| redact(v, secrets, f)),
        _ => {}
    }
}

pub fn redact_text(text: &str, secrets: &[String], f: &dyn Fn(&str) -> String) -> String {
    let mut out = text.to_string();
    // Longest first, so a secret that contains another is replaced whole.
    let mut ordered: Vec<&String> = secrets.iter().filter(|s| s.len() >= 4).collect();
    ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in ordered {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), &f(secret));
        }
    }
    out
}

/// A value counts as "present" for `error_path`: not null, not an empty
/// string, array or object, and not `false`.
pub fn is_present(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn concrete(root: &Value, path: &str) -> Vec<String> {
        find(root, path).into_iter().map(|(p, _)| p).collect()
    }

    #[test]
    fn paths_fan_out_and_report_where_they_went() {
        let data = json!({
            "connection_uris": [{"connection_uri": "postgres://a"}, {"connection_uri": "postgres://b"}],
            "data": {"variables": {"DATABASE_URL": "x", "PORT": "3000"}},
            "images": [{"url": "u1"}]
        });
        assert_eq!(concrete(&data, "connection_uris[].connection_uri"), ["connection_uris[0].connection_uri", "connection_uris[1].connection_uri"]);
        assert_eq!(concrete(&data, "connection_uris[1].connection_uri"), ["connection_uris[1].connection_uri"]);
        assert_eq!(concrete(&data, "data.variables.*"), ["data.variables.DATABASE_URL", "data.variables.PORT"]);
        assert_eq!(concrete(&data, "data.variables.PORT"), ["data.variables.PORT"]);
        assert!(concrete(&data, "missing[].x").is_empty());
        assert_eq!(find(&data, "images[].url")[0].1, "u1");
    }

    #[test]
    fn strings_are_replaced_in_place() {
        let mut data = json!({"a": {"b": ["s1", 2, "s3"]}, "c": "keep"});
        replace_strings(&mut data, "a.b[]", &|s| format!("<{}>", s.len()));
        assert_eq!(data, json!({"a": {"b": ["<2>", 2, "<2>"]}, "c": "keep"}));
    }

    #[test]
    fn echoed_secrets_are_redacted_anywhere() {
        let mut data = json!({"envVar": {"key": "DATABASE_URL", "value": "postgres://u:hunter22@h/db"}, "note": "token abcd1234 used"});
        let secrets = vec!["postgres://u:hunter22@h/db".to_string(), "abcd1234".to_string()];
        redact(&mut data, &secrets, &|s| format!("<{}>", s.len()));
        assert_eq!(data, json!({"envVar": {"key": "DATABASE_URL", "value": "<26>"}, "note": "token <8> used"}));
    }

    #[test]
    fn presence() {
        assert!(!is_present(&json!(null)));
        assert!(!is_present(&json!([])));
        assert!(is_present(&json!([{"message": "Not Authorized"}])));
    }
}
