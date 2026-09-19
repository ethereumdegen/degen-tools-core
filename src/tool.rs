use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::errors::DegenError;

const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Ceiling on a tool-declared timeout. A package is third-party content, so the
/// bound it asks for is a request, not an instruction.
const MAX_TIMEOUT_SECS: u64 = 600;

/// One HTTP tool, in the `api_tools/*.json` format metalcraft integration packs
/// use (metalcraft-agent `src/tools/http_api.rs`), so a package runs the same in
/// degen-tools and in the agent. `save` is degen-tools' addition; the agent ignores
/// fields it does not know.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "empty_schema")]
    pub parameters: Value,
    #[serde(default = "default_body_mapping")]
    pub body_mapping: String,
    #[serde(default)]
    pub body_template: Option<String>,
    #[serde(default)]
    pub body_defaults: Map<String, Value>,
    /// For `body_mapping == "params_nested"`: argument name → dotted body path.
    #[serde(default)]
    pub param_paths: HashMap<String, String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Response paths holding media URLs to download, e.g. `images[].url`.
    #[serde(default)]
    pub save: Vec<String>,
    /// Response paths holding a file's content inline rather than a URL to it
    /// (SVG markup, CSV, source text), written to files the way `save` writes
    /// downloads, and replaced in the printed response by a short note so a
    /// large document does not flood an agent's context.
    #[serde(default)]
    pub save_inline: Vec<InlineSave>,
    /// Response paths holding secrets (passwords, connection strings, tokens).
    /// They are masked in printed output and can be stored with `--save-secret`.
    #[serde(default)]
    pub secret_paths: Vec<String>,
    /// For APIs that answer 200 with a failure in the body (GraphQL `errors`):
    /// a non-empty value here fails the call.
    #[serde(default)]
    pub error_path: Option<String>,
    /// Hosts this tool may reach (`*.neon.tech` matches any subdomain). Required
    /// before credentials go to a URL whose host comes from a parameter.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Where the id of the thing this call created lives in the response
    /// (`data.id`). Its presence is what marks a tool as publishing something:
    /// a binary with a ledger counts those calls and records what to delete.
    #[serde(default)]
    pub post_id_path: Option<String>,
    /// Parameters whose value is a local file path rather than a value to send
    /// (`media`, `files[0]`). Only meaningful with `body_mapping: multipart`.
    #[serde(default)]
    pub file_params: Vec<String>,
    /// With `multipart`: pack every non-file parameter into this one field as
    /// JSON, instead of sending them as separate form fields. Discord wants
    /// `payload_json`; X wants plain fields, so it leaves this unset.
    #[serde(default)]
    pub payload_json_field: Option<String>,
}

/// One `save_inline` entry: where the content is and what file type it is.
#[derive(Debug, Clone, Deserialize)]
pub struct InlineSave {
    /// Response path, e.g. `data[].svg`.
    pub path: String,
    /// File extension to write, e.g. `svg`.
    pub ext: String,
}

impl InlineSave {
    /// A package is third-party content: its extension must be a plain one,
    /// never a path fragment.
    pub fn valid_ext(&self) -> bool {
        !self.ext.is_empty() && self.ext.len() <= 5 && self.ext.chars().all(|c| c.is_ascii_alphanumeric())
    }
}

fn empty_schema() -> Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

fn default_body_mapping() -> String {
    "params".to_string()
}

/// Body mappings this runner implements.
pub const SUPPORTED_BODY_MAPPINGS: &[&str] = &["none", "params", "params_nested", "template", "multipart"];

/// A file part of a multipart request: the field name, and the local path the
/// caller named.
pub struct FilePart {
    pub field: String,
    pub path: PathBuf,
}

/// What a `multipart` request carries: files read from disk, plus the ordinary
/// fields (or one field holding them all as JSON, which is how Discord takes a
/// message that has an attachment).
pub struct Multipart {
    pub files: Vec<FilePart>,
    pub fields: Vec<(String, String)>,
}

/// A request ready to send.
pub struct PreparedRequest {
    pub method: reqwest::Method,
    pub url: String,
    /// The URL before credentials are substituted — the only form safe to print.
    pub display_url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
    /// Set instead of `body` when the tool's mapping is `multipart`.
    pub multipart: Option<Multipart>,
    pub timeout: Duration,
}

impl ToolConfig {
    /// What the tool declared, clamped to [`MAX_TIMEOUT_SECS`]; `0`/absent is the default.
    pub fn timeout(&self) -> Duration {
        let secs = match self.timeout_secs {
            Some(s) if s > 0 => s.min(MAX_TIMEOUT_SECS),
            _ => DEFAULT_TIMEOUT_SECS,
        };
        Duration::from_secs(secs)
    }

    /// The native handler this tool names, if it is one: `"method": "NATIVE"`
    /// with `"url": "native:<id>"`. Everything else is one HTTP request.
    pub fn native_handler(&self) -> Option<&str> {
        self.method.eq_ignore_ascii_case("NATIVE").then(|| self.url.strip_prefix("native:")).flatten()
    }

    /// The credentials this tool's own text names (`$NEON_API_KEY` in the URL, a
    /// header, or `body_defaults`), limited to what the package declares. The
    /// runner resolves these before substitution starts.
    pub fn referenced_env(&self, allowed: &[String]) -> Vec<String> {
        let mut text = vec![self.url.clone()];
        text.extend(self.headers.values().cloned());
        collect_strings(&Value::Object(self.body_defaults.clone()), &mut text);
        allowed
            .iter()
            .filter(|name| text.iter().any(|t| t.contains(&format!("${name}"))))
            .cloned()
            .collect()
    }

    /// `lookup` resolves a credential name to its value; `carries_secrets` says
    /// the arguments hold stored credentials (`--secret`).
    pub fn prepare(
        &self,
        args: &Map<String, Value>,
        allowed_env: &[String],
        lookup: &dyn Fn(&str) -> Option<String>,
        carries_secrets: bool,
    ) -> Result<PreparedRequest, DegenError> {
        let method: reqwest::Method = self.method.to_ascii_uppercase().parse().map_err(|_| {
            DegenError::InvalidPackage(format!(
                "tool '{}' has invalid HTTP method '{}'",
                self.name, self.method
            ))
        })?;
        if !SUPPORTED_BODY_MAPPINGS.contains(&self.body_mapping.as_str()) {
            return Err(DegenError::InvalidPackage(format!(
                "tool '{}' uses body_mapping \"{}\", which {} does not support",
                self.name, self.body_mapping, crate::app().name
            )));
        }

        let display_url = self.expand_url(args);
        let url = expand_env(&display_url, allowed_env, lookup)?;
        let headers = self
            .headers
            .iter()
            .map(|(k, v)| Ok((k.clone(), expand_env(v, allowed_env, lookup)?)))
            .collect::<Result<Vec<_>, DegenError>>()?;
        self.check_host(&url, &display_url, allowed_env, carries_secrets)?;
        let defaults = match expand_env_in_value(&Value::Object(self.body_defaults.clone()), allowed_env, lookup)? {
            Value::Object(map) => map,
            _ => Map::new(),
        };

        Ok(PreparedRequest {
            method,
            url,
            display_url,
            headers,
            body: if self.body_mapping == "multipart" { None } else { self.build_body_with(args, &defaults) },
            multipart: if self.body_mapping == "multipart" { Some(self.build_multipart(args, &defaults)?) } else { None },
            timeout: self.timeout(),
        })
    }

    /// Split the arguments into files to read and fields to send. `param_paths`
    /// renames a parameter to the field the API wants, the way it already names
    /// a body path elsewhere: Discord takes attachments as `files[0]`, which is
    /// not something to make a caller type.
    fn build_multipart(&self, args: &Map<String, Value>, defaults: &Map<String, Value>) -> Result<Multipart, DegenError> {
        let url_params = self.url_placeholder_names();
        let field_for = |key: &str| self.param_paths.get(key).cloned().unwrap_or_else(|| key.to_string());
        let mut files = Vec::new();
        let mut rest = defaults.clone();
        for (key, value) in args {
            if url_params.contains(key) || !provided(value) {
                continue;
            }
            if self.file_params.contains(key) {
                let path = value.as_str().ok_or_else(|| {
                    DegenError::InvalidArgs(format!("{}: --{key} takes the path of a file, not {value}", self.name))
                })?;
                files.push(FilePart { field: field_for(key), path: PathBuf::from(path) });
            } else {
                rest.insert(field_for(key), value.clone());
            }
        }
        let fields = match &self.payload_json_field {
            Some(field) if !rest.is_empty() => vec![(field.clone(), Value::Object(rest).to_string())],
            Some(_) => Vec::new(),
            None => rest.into_iter().map(|(k, v)| (k, value_text(&v))).collect(),
        };
        Ok(Multipart { files, fields })
    }

    /// Credentials only go where the package author fixed them to go. A tool whose
    /// host is written into its URL is fine as is; a tool that takes its host from
    /// a parameter must list `allowed_hosts`, or anyone who can pick the argument
    /// could point the credential at their own server. The check runs on the URL
    /// as the HTTP client parses it, so tricks like `evil.example\\.neon.tech` or
    /// `x.neon.tech@evil.example` are judged by the host really contacted.
    fn check_host(&self, url: &str, display_url: &str, allowed_env: &[String], carries_secrets: bool) -> Result<(), DegenError> {
        let refused = |why: String| DegenError::InvalidArgs(format!("refusing to call {display_url}: {why}"));
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .ok_or_else(|| refused("it is not a valid http(s) URL".to_string()))?;
        if !self.allowed_hosts.is_empty() {
            if self.allowed_hosts.iter().any(|pattern| host_matches(&host, pattern)) {
                return Ok(());
            }
            return Err(refused(format!(
                "{host} is not one of the hosts {} may reach ({})",
                self.name,
                self.allowed_hosts.join(", ")
            )));
        }
        let uses_credentials = std::iter::once(&self.url)
            .chain(self.headers.values())
            .any(|text| allowed_env.iter().any(|name| text.contains(&format!("${name}"))));
        if host_of(&self.url).is_none() && self.host_credential(allowed_env).is_none() && (uses_credentials || carries_secrets) {
            return Err(refused(format!(
                "{} takes its host from a parameter and declares no allowed_hosts, so it may not carry credentials",
                self.name
            )));
        }
        Ok(())
    }

    /// Fill `{param}` placeholders from args. Null or empty arguments count as
    /// not provided, so an optional `?name={name}` is dropped rather than sent
    /// as `?name=` (which some APIs read as "match the empty string"). Values in
    /// the query string are percent-encoded; values in the path are not, so a
    /// model id like `fal-ai/flux/schnell` keeps its slashes.
    pub fn expand_url(&self, args: &Map<String, Value>) -> String {
        let query_start = self.url.find('?').unwrap_or(self.url.len());
        let mut out = String::with_capacity(self.url.len());
        let mut pos = 0;
        while let Some(open) = self.url[pos..].find('{').map(|i| i + pos) {
            let Some(close) = self.url[open..].find('}').map(|i| i + open) else {
                break;
            };
            out.push_str(&self.url[pos..open]);
            let name = &self.url[open + 1..close];
            match args.get(name).filter(|v| provided(v)) {
                Some(value) => {
                    let text = value_text(value);
                    if open > query_start {
                        out.push_str(&percent_encode(&text));
                    } else {
                        out.push_str(&text);
                    }
                }
                None => out.push_str(&self.url[open..=close]),
            }
            pos = close + 1;
        }
        out.push_str(&self.url[pos..]);
        clean_unexpanded_placeholders(&out)
    }

    /// Names of `{placeholder}` tokens in the URL. Those arguments are consumed
    /// by the URL and never also written into the body.
    fn url_placeholder_names(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut rest = self.url.as_str();
        while let Some(open) = rest.find('{') {
            rest = &rest[open + 1..];
            let Some(close) = rest.find('}') else { break };
            if close > 0 {
                out.insert(rest[..close].to_string());
            }
            rest = &rest[close + 1..];
        }
        out
    }

    /// The credential a URL starts with, when its host is the user's own
    /// setting (`$STARCAST_BASE_URL/api/v1/...` for a self-hosted service).
    /// The user stored that value, so the host is as fixed as a literal one.
    pub fn host_credential<'a>(&self, allowed_env: &'a [String]) -> Option<&'a str> {
        let rest = self.url.strip_prefix('$')?;
        allowed_env
            .iter()
            .map(String::as_str)
            .find(|name| rest.strip_prefix(name).is_some_and(|after| after.is_empty() || after.starts_with('/')))
    }

    #[cfg(test)]
    pub fn build_body(&self, args: &Map<String, Value>) -> Option<Value> {
        self.build_body_with(args, &self.body_defaults)
    }

    fn build_body_with(&self, args: &Map<String, Value>, defaults: &Map<String, Value>) -> Option<Value> {
        let url_params = self.url_placeholder_names();
        match self.body_mapping.as_str() {
            "none" => None,
            "params" => {
                let mut merged = defaults.clone();
                for (k, v) in args {
                    if !url_params.contains(k) {
                        merged.insert(k.clone(), v.clone());
                    }
                }
                Some(Value::Object(merged))
            }
            "params_nested" => {
                let mut root = defaults.clone();
                for (key, value) in args {
                    if url_params.contains(key) || !provided(value) {
                        continue;
                    }
                    let path = self.param_paths.get(key).map(String::as_str).unwrap_or(key);
                    insert_at_path(&mut root, path, value.clone());
                }
                Some(Value::Object(root))
            }
            "template" => match &self.body_template {
                Some(template) => {
                    let mut result = template.clone();
                    for (key, value) in args {
                        result = result.replace(&format!("{{{key}}}"), &value_text(value));
                    }
                    serde_json::from_str(&result).ok()
                }
                None => Some(Value::Object(args.clone())),
            },
            _ => Some(Value::Object(args.clone())),
        }
    }
}

fn provided(value: &Value) -> bool {
    !(value.is_null() || value.as_str() == Some(""))
}

fn value_text(value: &Value) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string())
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Drop query segments whose placeholder was never filled.
fn clean_unexpanded_placeholders(url: &str) -> String {
    let Some(qmark) = url.find('?') else {
        return url.to_string();
    };
    let (base, query) = url.split_at(qmark + 1);
    let kept: Vec<&str> = query.split('&').filter(|seg| !seg.contains('{')).collect();
    if kept.is_empty() {
        base.trim_end_matches('?').to_string()
    } else {
        format!("{base}{}", kept.join("&"))
    }
}

/// Write `value` at a dotted `path`, creating intermediate objects.
fn insert_at_path(root: &mut Map<String, Value>, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut current = root;
    for seg in parents {
        let slot = current
            .entry(seg.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !slot.is_object() {
            *slot = Value::Object(Map::new());
        }
        current = slot.as_object_mut().expect("just ensured object");
    }
    current.insert(last.to_string(), value);
}

/// Substitute `$NAME` with its stored credential — only for names the package
/// declares in `requires_env`. A package is someone else's code: without that
/// limit any package could put `$CLOUDFLARE_API_TOKEN` in a header and send it
/// to a host of its choosing. Undeclared `$NAME`s are left exactly as written.
pub fn expand_env(
    s: &str,
    allowed: &[String],
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, DegenError> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        let name = &after[..end];
        if !name.is_empty() && allowed.iter().any(|a| a == name) {
            let value = lookup(name)
                .ok_or_else(|| DegenError::CredentialNotFound(name.to_string()))?;
            out.push_str(&value);
        } else {
            out.push('$');
            out.push_str(name);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `$NAME` in the string values of a tool's fixed body (`body_defaults`), e.g.
/// Cloudflare's `{"account": {"id": "$CLOUDFLARE_ACCOUNT_ID"}}`. Arguments are
/// never expanded, and only declared names are.
fn expand_env_in_value(value: &Value, allowed: &[String], lookup: &dyn Fn(&str) -> Option<String>) -> Result<Value, DegenError> {
    Ok(match value {
        Value::String(s) if s.contains('$') => Value::String(expand_env(s, allowed, lookup)?),
        Value::Array(items) => Value::Array(items.iter().map(|v| expand_env_in_value(v, allowed, lookup)).collect::<Result<_, _>>()?),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| Ok((k.clone(), expand_env_in_value(v, allowed, lookup)?)))
                .collect::<Result<_, DegenError>>()?,
        ),
        other => other.clone(),
    })
}

/// Every string in a JSON value, for scanning `body_defaults`.
fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// `*.example.com` matches any subdomain of example.com (not example.com itself);
/// anything else must match exactly.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

/// The host a URL reaches, lowercased; `None` if it has none (or it is templated).
pub fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = host_port.split(':').next()?;
    (!host.is_empty() && !host.contains('{')).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(v: Value) -> ToolConfig {
        serde_json::from_value(v).unwrap()
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn creds(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn optional_query_params_are_dropped_and_values_encoded() {
        let t = tool(json!({
            "name": "t", "method": "GET",
            "url": "https://api.example.com/zones/{zone_id}/records?type={type}&name={name}"
        }));
        assert_eq!(
            t.expand_url(&args(json!({"zone_id": "z1", "name": "a b&c"}))),
            "https://api.example.com/zones/z1/records?name=a%20b%26c"
        );
        assert_eq!(
            t.expand_url(&args(json!({"zone_id": "z1", "type": ""}))),
            "https://api.example.com/zones/z1/records"
        );
    }

    #[test]
    fn path_values_keep_their_slashes() {
        let t = tool(json!({"name": "t", "method": "POST", "url": "https://fal.run/{model}"}));
        assert_eq!(
            t.expand_url(&args(json!({"model": "fal-ai/flux/schnell"}))),
            "https://fal.run/fal-ai/flux/schnell"
        );
    }

    #[test]
    fn url_params_stay_out_of_the_body() {
        let t = tool(json!({
            "name": "t", "method": "POST", "url": "https://fal.run/{model}",
            "body_defaults": {"num_images": 1}
        }));
        let body = t.build_body(&args(json!({"model": "m", "prompt": "p"}))).unwrap();
        assert_eq!(body, json!({"num_images": 1, "prompt": "p"}));
    }

    #[test]
    fn params_nested_writes_paths_and_skips_blanks() {
        let t = tool(json!({
            "name": "t", "method": "POST", "url": "https://x.example/run",
            "body_mapping": "params_nested",
            "body_defaults": {"payload": {"model_key": "k"}},
            "param_paths": {"prompt": "payload.params.prompt"}
        }));
        let body = t.build_body(&args(json!({"prompt": "say \"hi\"", "seed": null}))).unwrap();
        assert_eq!(body, json!({"payload": {"model_key": "k", "params": {"prompt": "say \"hi\""}}}));
    }

    #[test]
    fn only_declared_credentials_are_substituted() {
        let c = creds(&[("FAL_KEY", "secret"), ("CLOUDFLARE_API_TOKEN", "cf")]);
        let allowed = vec!["FAL_KEY".to_string()];
        assert_eq!(expand_env("Key $FAL_KEY", &allowed, &c).unwrap(), "Key secret");
        assert_eq!(
            expand_env("Bearer $CLOUDFLARE_API_TOKEN", &allowed, &c).unwrap(),
            "Bearer $CLOUDFLARE_API_TOKEN"
        );
        assert_eq!(expand_env("$select=id", &allowed, &c).unwrap(), "$select=id");
    }

    #[test]
    fn a_declared_but_missing_credential_is_an_error_not_a_blank_header() {
        let allowed = vec!["STARFIRE_TEST_UNSET_KEY_7Q".to_string()];
        let err = expand_env("Key $STARFIRE_TEST_UNSET_KEY_7Q", &allowed, &creds(&[]));
        assert!(matches!(err, Err(DegenError::CredentialNotFound(_))));
    }

    #[test]
    fn display_url_never_holds_the_credential() {
        let t = tool(json!({
            "name": "t", "method": "GET", "url": "https://x.example/q?key=$FAL_KEY",
            "headers": {"Authorization": "Key $FAL_KEY"}
        }));
        let req = t
            .prepare(&Map::new(), &["FAL_KEY".to_string()], &creds(&[("FAL_KEY", "s3cret")]), false)
            .unwrap();
        assert_eq!(req.url, "https://x.example/q?key=s3cret");
        assert!(!req.display_url.contains("s3cret"));
        assert_eq!(req.headers, vec![("Authorization".to_string(), "Key s3cret".to_string())]);
    }

    fn neon_sql() -> ToolConfig {
        tool(json!({
            "name": "neon_sql", "method": "POST", "url": "https://api.{region}/sql",
            "headers": {"Neon-Connection-String": "$NEON_DATABASE_URL"},
            "allowed_hosts": ["*.neon.tech"]
        }))
    }

    #[test]
    fn a_parameter_host_must_be_allowed() {
        let allowed = vec!["NEON_DATABASE_URL".to_string()];
        let c = creds(&[("NEON_DATABASE_URL", "postgres://u:p@h/db")]);
        let t = neon_sql();
        assert!(t.prepare(&args(json!({"region": "us-east-2.aws.neon.tech"})), &allowed, &c, false).is_ok());
        for evil in ["evil.example", "evil.example/x.neon.tech", "evil.example#.neon.tech", "x.neon.tech@evil.example", "evil.example\\.neon.tech", "neon.tech.evil.example"] {
            let err = t.prepare(&args(json!({"region": evil})), &allowed, &c, false);
            assert!(err.is_err(), "{evil} was allowed");
        }
    }

    #[test]
    fn a_parameter_host_without_an_allowlist_gets_no_credentials() {
        let allowed = vec!["FAL_KEY".to_string()];
        let c = creds(&[("FAL_KEY", "k")]);
        let with_key = tool(json!({"name": "t", "method": "GET", "url": "https://{host}/x", "headers": {"Authorization": "Key $FAL_KEY"}}));
        assert!(with_key.prepare(&args(json!({"host": "fal.run"})), &allowed, &c, false).is_err());
        let open = tool(json!({"name": "t", "method": "GET", "url": "https://{host}/x"}));
        assert!(open.prepare(&args(json!({"host": "fal.run"})), &allowed, &c, false).is_ok());
        assert!(open.prepare(&args(json!({"host": "fal.run"})), &allowed, &c, true).is_err());
    }

    #[test]
    fn a_host_from_the_users_own_credential_is_fixed() {
        let allowed = vec!["STARCAST_BASE_URL".to_string(), "STARCAST_API_KEY".to_string()];
        let c = creds(&[("STARCAST_BASE_URL", "https://starcast.example.com"), ("STARCAST_API_KEY", "sck_x")]);
        let t = tool(json!({
            "name": "t", "method": "GET", "url": "$STARCAST_BASE_URL/api/v1/workspaces",
            "headers": {"Authorization": "Bearer $STARCAST_API_KEY"}
        }));
        let req = t.prepare(&Map::new(), &allowed, &c, false).unwrap();
        assert_eq!(req.url, "https://starcast.example.com/api/v1/workspaces");
        assert_eq!(t.host_credential(&allowed), Some("STARCAST_BASE_URL"));
        // A prefix that merely starts with a declared name is not the same thing.
        let other = tool(json!({"name": "t", "method": "GET", "url": "$STARCAST_BASE_URL_EVIL/x", "headers": {"Authorization": "Bearer $STARCAST_API_KEY"}}));
        assert_eq!(other.host_credential(&allowed), None);
    }

    #[test]
    fn fixed_body_values_take_credentials_but_arguments_do_not() {
        let allowed = vec!["CLOUDFLARE_ACCOUNT_ID".to_string()];
        let c = creds(&[("CLOUDFLARE_ACCOUNT_ID", "acc123")]);
        let t = tool(json!({
            "name": "t", "method": "POST", "url": "https://api.cloudflare.com/client/v4/zones",
            "body_mapping": "params_nested", "body_defaults": {"account": {"id": "$CLOUDFLARE_ACCOUNT_ID"}, "type": "full"}
        }));
        let req = t.prepare(&args(json!({"name": "$CLOUDFLARE_ACCOUNT_ID"})), &allowed, &c, false).unwrap();
        assert_eq!(req.body.unwrap(), json!({"account": {"id": "acc123"}, "type": "full", "name": "$CLOUDFLARE_ACCOUNT_ID"}));
    }

    #[test]
    fn host_patterns() {
        assert!(host_matches("api.us-east-2.aws.neon.tech", "*.neon.tech"));
        assert!(!host_matches("neon.tech", "*.neon.tech"));
        assert!(!host_matches("evilneon.tech", "*.neon.tech"));
        assert!(host_matches("fal.run", "FAL.run"));
    }

    #[test]
    fn host_of_ignores_userinfo_and_templates() {
        assert_eq!(host_of("https://a@evil.example/x").as_deref(), Some("evil.example"));
        assert_eq!(host_of("https://{host}/x"), None);
        assert_eq!(host_of("https://Fal.run:443/m").as_deref(), Some("fal.run"));
    }

    #[test]
    fn a_native_tool_is_recognised_by_its_method_and_url() {
        let native = tool(json!({"name": "up", "method": "NATIVE", "url": "native:x_upload_video"}));
        assert_eq!(native.native_handler(), Some("x_upload_video"));

        let http = tool(json!({"name": "up", "method": "POST", "url": "https://api.example/upload"}));
        assert_eq!(http.native_handler(), None);

        // A tool that says NATIVE without naming a handler is not one; it will
        // fail as an invalid HTTP method rather than run something arbitrary.
        let empty = tool(json!({"name": "up", "method": "NATIVE", "url": "https://api.example/upload"}));
        assert_eq!(empty.native_handler(), None);
    }

    #[test]
    fn multipart_separates_files_from_fields_and_renames_them() {
        let t = tool(json!({
            "name": "up",
            "method": "POST",
            "url": "https://api.example/channels/{channel_id}/messages",
            "body_mapping": "multipart",
            "file_params": ["file"],
            "param_paths": {"file": "files[0]"},
            "body_defaults": {"allowed_mentions": {"parse": []}},
            "payload_json_field": "payload_json"
        }));
        let req = t
            .prepare(&args(json!({"channel_id": "777", "file": "./pic.png", "content": "hi"})), &[], &|_| None, false)
            .unwrap();
        let multipart = req.multipart.expect("a multipart tool prepares a form");

        assert_eq!(multipart.files.len(), 1);
        assert_eq!(multipart.files[0].field, "files[0]", "the API's field name, not the parameter's");
        assert_eq!(multipart.files[0].path.to_str(), Some("./pic.png"));

        // The channel id went into the URL, so it is not also a form field.
        assert_eq!(multipart.fields.len(), 1);
        let (name, json_body) = &multipart.fields[0];
        assert_eq!(name, "payload_json");
        let packed: Value = serde_json::from_str(json_body).unwrap();
        assert_eq!(packed["content"], json!("hi"));
        assert_eq!(packed["allowed_mentions"], json!({"parse": []}), "defaults ride along");
        assert_eq!(packed.get("channel_id"), None);
        assert!(req.body.is_none(), "a multipart request has no JSON body");
    }

    #[test]
    fn multipart_without_payload_packing_sends_plain_fields() {
        let t = tool(json!({
            "name": "up",
            "method": "POST",
            "url": "https://api.example/2/media/upload",
            "body_mapping": "multipart",
            "file_params": ["media"],
            "body_defaults": {"media_category": "tweet_image"}
        }));
        let req = t.prepare(&args(json!({"media": "/tmp/a.png"})), &[], &|_| None, false).unwrap();
        let multipart = req.multipart.unwrap();
        assert_eq!(multipart.files[0].field, "media");
        assert_eq!(multipart.fields, vec![("media_category".to_string(), "tweet_image".to_string())]);
    }

    #[test]
    fn a_file_parameter_must_be_a_path() {
        let t = tool(json!({
            "name": "up",
            "method": "POST",
            "url": "https://api.example/upload",
            "body_mapping": "multipart",
            "file_params": ["media"]
        }));
        assert!(t.prepare(&args(json!({"media": 42})), &[], &|_| None, false).is_err());
    }
}
