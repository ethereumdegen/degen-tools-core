use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::errors::DegenError;
use crate::run::RunOptions;
use crate::tool::ToolConfig;

fn invalid(msg: String) -> DegenError {
    DegenError::InvalidArgs(msg)
}

/// Turn `--name value` tokens into a JSON argument object, typed by the tool's
/// parameter schema. `--json` supplies a base object that flags override.
///
/// `--out`, `--json`, `--secret`, `--save-secret` and `--cred` are degen-tools'
/// own options. They normally go before the tool name, but are accepted after it
/// too when the tool has no parameter of that name. Required parameters are
/// checked separately by [`require`], once `--secret` values are filled in.
pub fn parse(tool: &ToolConfig, tokens: &[String], opts: &mut RunOptions) -> Result<Map<String, Value>, DegenError> {
    let props = tool
        .parameters
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let open = tool.parameters.get("additionalProperties") == Some(&Value::Bool(true));

    let mut json = opts.json.clone();
    let mut flags = Map::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        i += 1;
        let Some(flag) = tok.strip_prefix("--") else {
            return Err(invalid(format!(
                "unexpected argument '{tok}' — tool parameters are passed as --name value\n\n  \
                 Parameters: {} skill {}",
                crate::app().name,
                tool.name
            )));
        };
        let (raw_name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        let name = resolve_name(raw_name, &props);
        let ty = name
            .as_ref()
            .and_then(|n| props[n].get("type"))
            .and_then(Value::as_str);

        let value = match inline {
            Some(v) => v,
            None => match tokens.get(i).filter(|t| !t.starts_with("--")) {
                Some(v) => {
                    i += 1;
                    v.clone()
                }
                None if ty == Some("boolean") => "true".to_string(),
                None => return Err(invalid(format!("--{raw_name} needs a value"))),
            },
        };

        let Some(name) = name else {
            match raw_name {
                "json" => json = Some(value),
                "out" => opts.out = Some(PathBuf::from(value)),
                "secret" => opts.secrets.push(value),
                "save-secret" | "save_secret" => opts.save_secrets.push(value),
                "cred" => opts.creds.push(value),
                _ if open => {
                    let v = serde_json::from_str(&value).unwrap_or(Value::String(value));
                    flags.insert(raw_name.to_string(), v);
                }
                _ => return Err(unknown_param(tool, raw_name, &props)),
            }
            continue;
        };

        let prop = &props[&name];
        if ty == Some("array") {
            match serde_json::from_str::<Value>(&value) {
                Ok(Value::Array(a)) => {
                    flags.insert(name, Value::Array(a));
                }
                _ => {
                    // Repeated flags build the array: --tag a --tag b
                    let slot = flags.entry(name).or_insert_with(|| Value::Array(Vec::new()));
                    if let Value::Array(a) = slot {
                        a.push(Value::String(value));
                    }
                }
            }
        } else {
            flags.insert(name.clone(), coerce(&name, &value, prop)?);
        }
    }

    let mut args = match json {
        Some(j) => parse_json_arg(&j)?,
        None => Map::new(),
    };
    args.extend(flags);
    Ok(args)
}

/// Arguments given as JSON (the local API) name only parameters the tool has,
/// unless its schema is open.
pub fn check_known(tool: &ToolConfig, args: &Map<String, Value>) -> Result<(), DegenError> {
    if tool.parameters.get("additionalProperties") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    let props = tool.parameters.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
    match args.keys().find(|k| !props.contains_key(*k)) {
        Some(k) => Err(unknown_param(tool, k, &props)),
        None => Ok(()),
    }
}

/// Every required parameter is present and non-empty.
pub fn require(tool: &ToolConfig, args: &Map<String, Value>) -> Result<(), DegenError> {
    let required = tool
        .parameters
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let missing: Vec<String> = required
        .iter()
        .filter_map(Value::as_str)
        .filter(|r| args.get(*r).is_none_or(|v| v.is_null() || v.as_str() == Some("")))
        .map(|r| format!("--{r}"))
        .collect();
    if !missing.is_empty() {
        return Err(invalid(format!(
            "{} requires {}\n\n  Parameters: {} skill {}",
            tool.name,
            missing.join(", "),
            crate::app().name,
            tool.name
        )));
    }
    Ok(())
}

/// `--zone-id` finds `zone_id` when the schema has no `zone-id`.
fn resolve_name(raw: &str, props: &Map<String, Value>) -> Option<String> {
    if props.contains_key(raw) {
        return Some(raw.to_string());
    }
    let underscored = raw.replace('-', "_");
    props.contains_key(&underscored).then_some(underscored)
}

fn unknown_param(tool: &ToolConfig, name: &str, props: &Map<String, Value>) -> DegenError {
    let known: Vec<String> = props.keys().map(|k| format!("--{k}")).collect();
    let known = if known.is_empty() { "(none)".to_string() } else { known.join(", ") };
    invalid(format!(
        "{} has no parameter --{name}\n\n  Parameters: {known}\n  Details:    {} skill {}",
        tool.name,
        crate::app().name,
        tool.name
    ))
}

fn parse_json_arg(raw: &str) -> Result<Map<String, Value>, DegenError> {
    let text = match raw.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)?,
        None => raw.to_string(),
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(invalid("--json must be a JSON object".to_string())),
        Err(e) => Err(invalid(format!("--json is not valid JSON: {e}"))),
    }
}

fn coerce(name: &str, raw: &str, prop: &Value) -> Result<Value, DegenError> {
    let value = match prop.get("type").and_then(Value::as_str) {
        Some("string") => Value::String(raw.to_string()),
        Some("integer") => raw
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| invalid(format!("--{name} expects an integer, got '{raw}'")))?,
        Some("number") => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| invalid(format!("--{name} expects a number, got '{raw}'")))?,
        Some("boolean") => match raw {
            "true" | "yes" | "1" => Value::Bool(true),
            "false" | "no" | "0" => Value::Bool(false),
            _ => return Err(invalid(format!("--{name} expects true or false, got '{raw}'"))),
        },
        Some("object") => serde_json::from_str::<Value>(raw)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| invalid(format!("--{name} expects a JSON object")))?,
        _ => serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string())),
    };
    if let Some(options) = prop.get("enum").and_then(Value::as_array)
        && !options.contains(&value)
    {
        let list: Vec<String> = options.iter().map(|o| o.as_str().map(str::to_string).unwrap_or_else(|| o.to_string())).collect();
        return Err(invalid(format!("--{name} must be one of: {}", list.join(", "))));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(params: Value) -> ToolConfig {
        serde_json::from_value(json!({
            "name": "t", "method": "POST", "url": "https://x.example", "parameters": params
        }))
        .unwrap()
    }

    fn toks(s: &[&str]) -> Vec<String> {
        s.iter().map(|t| t.to_string()).collect()
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "num_images": {"type": "integer"},
                "guidance_scale": {"type": "number"},
                "proxied": {"type": "boolean"},
                "zone_id": {"type": "string"},
                "size": {"type": "string", "enum": ["square", "landscape_4_3"]},
                "tags": {"type": "array"}
            },
            "required": ["prompt"]
        })
    }

    #[test]
    fn flags_are_typed_by_the_schema() {
        let a = parse(
            &tool(schema()),
            &toks(&["--prompt", "123", "--num_images=2", "--guidance_scale", "3.5", "--proxied", "--zone-id", "z", "--tags", "a", "--tags", "b"]),
            &mut RunOptions::default(),
        )
        .unwrap();
        assert_eq!(
            Value::Object(a),
            json!({"prompt": "123", "num_images": 2, "guidance_scale": 3.5, "proxied": true, "zone_id": "z", "tags": ["a", "b"]})
        );
    }

    #[test]
    fn json_is_the_base_and_flags_override() {
        let mut opts = RunOptions { json: Some(r#"{"prompt": "json", "extra": 1}"#.to_string()), ..Default::default() };
        let a = parse(&tool(schema()), &toks(&["--prompt", "flag"]), &mut opts).unwrap();
        assert_eq!(Value::Object(a), json!({"prompt": "flag", "extra": 1}));
    }

    #[test]
    fn required_enum_and_unknown_are_reported() {
        let mut opts = RunOptions::default();
        let t = tool(schema());
        let empty = parse(&t, &toks(&[]), &mut opts).unwrap();
        assert!(require(&t, &empty).unwrap_err().to_string().contains("--prompt"));
        assert!(parse(&t, &toks(&["--prompt", "p", "--size", "huge"]), &mut opts).unwrap_err().to_string().contains("square"));
        assert!(parse(&t, &toks(&["--prompt", "p", "--nope", "1"]), &mut opts).unwrap_err().to_string().contains("no parameter --nope"));
        assert!(parse(&t, &toks(&["--prompt", "p", "loose"]), &mut opts).is_err());
    }

    #[test]
    fn open_schemas_pass_unknown_flags_through() {
        let t = tool(json!({"type": "object", "properties": {"model": {"type": "string"}}, "required": ["model"], "additionalProperties": true}));
        let a = parse(&t, &toks(&["--model", "m", "--prompt", "snow", "--num_images", "2"]), &mut RunOptions::default()).unwrap();
        assert_eq!(Value::Object(a), json!({"model": "m", "prompt": "snow", "num_images": 2}));
    }

    #[test]
    fn own_options_after_the_tool_name() {
        let mut opts = RunOptions::default();
        parse(&tool(schema()), &toks(&["--prompt", "p", "--out", "img/", "--secret", "prompt=K", "--save-secret", "N=a.b", "--cred", "A=B"]), &mut opts).unwrap();
        assert_eq!(opts.out, Some(PathBuf::from("img/")));
        assert_eq!((opts.secrets, opts.save_secrets, opts.creds), (vec!["prompt=K".to_string()], vec!["N=a.b".to_string()], vec!["A=B".to_string()]));
    }
}
