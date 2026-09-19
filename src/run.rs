use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::args;
use crate::auth;
use crate::config::CallContext;
use crate::errors::DegenError;
use crate::package::{self, Package};
use crate::paths;
use crate::tool::{InlineSave, Multipart, ToolConfig};

/// degen-tools' own `run` options (as opposed to the tool's parameters).
#[derive(Default)]
pub struct RunOptions {
    /// Where returned media goes.
    pub out: Option<PathBuf>,
    /// Base arguments as JSON, or `@file.json`.
    pub json: Option<String>,
    /// `PARAM=CREDENTIAL`: fill a parameter from a stored credential.
    pub secrets: Vec<String>,
    /// `NAME` or `NAME=PATH`: store a secret from the response as credential NAME.
    pub save_secrets: Vec<String>,
    /// `VAR=CREDENTIAL`: for this call, the package's `$VAR` reads credential CREDENTIAL.
    pub creds: Vec<String>,
    /// `--save-secret` writes to the global store rather than the project `.env`.
    pub global: bool,
    /// Act as this connected account (`x:handle`). degen-tools has no accounts
    /// and leaves it `None`.
    pub account: Option<String>,
}

/// What one tool call produced, with every secret already masked.
#[derive(Debug, serde::Serialize)]
pub struct Outcome {
    pub tool: String,
    pub package: String,
    /// The HTTP call succeeded and carried no errors at `error_path`.
    pub ok: bool,
    /// The upstream HTTP status.
    pub status: u16,
    /// Why the call counts as failed, when it does.
    pub error: Option<String>,
    /// The response: JSON as returned (masked), or a string when it was not JSON.
    pub response: Value,
    /// Local files written from media URLs in the response.
    pub saved_media: Vec<String>,
    /// Secrets stored from the response.
    pub stored_secrets: Vec<StoredSecret>,
    pub duration_ms: u128,
}

#[derive(Debug, serde::Serialize)]
pub struct StoredSecret {
    pub name: String,
    /// The response field it came from.
    pub from: String,
    /// The project `.env` path, or "the global store".
    pub stored_in: String,
}

/// `degen-tools run [options] <tool> [--param value ...]`
pub fn run(tool_ref: &str, tokens: &[String], mut opts: RunOptions) -> Result<(), DegenError> {
    let (pkg, tool) = package::find_tool(tool_ref)?;
    let args = args::parse(&tool, tokens, &mut opts)?;
    let outcome = execute(&pkg, &tool, args, &opts)?;

    for s in &outcome.stored_secrets {
        eprintln!("✓ stored {} as {} in {} (the value is not shown)", s.from, s.name, s.stored_in);
    }
    let shown = if outcome.saved_media.is_empty() || !outcome.ok {
        outcome.response.clone()
    } else {
        json!({ "saved": outcome.saved_media, "response": outcome.response })
    };
    match &shown {
        Value::String(text) if outcome.response.is_string() => print_text(text),
        v => println!("{}", pretty(v)),
    }
    match outcome.error {
        Some(error) => Err(DegenError::Http(error)),
        None => Ok(()),
    }
}

/// Call `tool` with `args` (already typed JSON). Validation problems are errors;
/// an upstream failure is an [`Outcome`] with `ok: false`, so its body can
/// still be shown.
pub fn execute(pkg: &Package, tool: &ToolConfig, mut args: Map<String, Value>, opts: &RunOptions) -> Result<Outcome, DegenError> {
    let started = std::time::Instant::now();
    let ctx = CallContext { package: pkg.id(), tool: &tool.name, account: opts.account.as_deref() };
    let resolver = crate::app().credentials;
    let aliases = pairs(&opts.creds, "--cred", "VAR=CREDENTIAL")?;
    for (var, cred) in &aliases {
        if !pkg.integration.requires_env.contains(var) {
            return Err(DegenError::InvalidArgs(format!(
                "--cred {var}=...: {} does not use {var} (it uses: {})",
                pkg.id(),
                pkg.integration.requires_env.join(", ")
            )));
        }
        may_receive(&pkg, cred)?;
    }
    // Resolved before anything is substituted: a resolver may have to refresh an
    // expired token first, and that failure has to surface as itself rather than
    // as a credential that looks unset.
    let mut values: HashMap<String, String> = HashMap::new();
    for var in tool.referenced_env(&pkg.integration.requires_env) {
        let actual = aliases.iter().find(|(v, _)| v == &var).map_or(var.as_str(), |(_, cred)| cred.as_str());
        if let Some(value) = resolver.resolve(actual, &ctx)? {
            values.insert(var.clone(), value);
        }
    }
    // Pre-resolved above; a `$NAME` that only appears once arguments are in the
    // URL still resolves, exactly as it did before, just without the early error.
    let lookup = |name: &str| match values.get(name) {
        Some(value) => Some(value.clone()),
        None => resolver.resolve(name, &ctx).ok().flatten(),
    };

    let secret_args = pairs(&opts.secrets, "--secret", "PARAM=CREDENTIAL")?;
    for (param, cred) in &secret_args {
        may_receive(&pkg, cred)?;
        let known = tool.parameters.pointer(&format!("/properties/{param}")).is_some()
            || tool.parameters.get("additionalProperties") == Some(&Value::Bool(true));
        if !known {
            return Err(DegenError::InvalidArgs(format!("--secret {param}=...: {} has no parameter --{param}", tool.name)));
        }
        let value = resolver.resolve(cred, &ctx)?.ok_or_else(|| DegenError::CredentialNotFound(cred.clone()))?;
        args.insert(param.clone(), Value::String(value));
    }
    args::require(&tool, &args)?;
    // The last gate before a request leaves. degen-tools allows everything;
    // degen-portal refuses, or holds the call for a human, and counts what a
    // sent one spent.
    match crate::app().policy.check(tool, &args, &ctx)? {
        crate::Verdict::Send => {}
        crate::Verdict::Hold(outcome) => return Ok(*outcome),
    }

    // A tool the binary implements itself. It runs behind the same gate, is
    // recorded the same way, and — because a package is third-party content —
    // only a package compiled into this binary may name one.
    if let Some(handler) = tool.native_handler() {
        return run_native(pkg, tool, handler, &args, &ctx, started);
    }

    let req = tool.prepare(&args, &pkg.integration.requires_env, &lookup, !secret_args.is_empty())?;
    // Every secret value this call sends, so an API that echoes one back
    // (an env var it just set, a token in an error message) never prints it.
    let mut req = req;
    // Signed once the request exists: an OAuth 1.0a credential is an HMAC over
    // the method, URL and parameters, so it cannot be written into a package
    // file the way a key in a header can.
    let signed = crate::app().signer.sign(&mut req, &ctx)?;
    let sensitive: Vec<String> = signed
        .into_iter()
        .chain(secret_args.iter().filter_map(|(param, _)| args.get(param).and_then(Value::as_str).map(str::to_string)))
        .chain(
            pkg.integration
                .requires_env
                .iter()
                // A base URL the user configured is an address, not a secret: masking
                // it would hide every link the API returns.
                .filter(|var| tool.host_credential(&pkg.integration.requires_env) != Some(var.as_str()))
                .filter(|var| std::iter::once(&tool.url).chain(tool.headers.values()).any(|t| t.contains(&format!("${var}"))))
                .filter_map(|var| lookup(var)),
        )
        .collect();
    let saves = opts.save_secrets.iter().map(|s| parse_save(s)).collect::<Result<Vec<_>, _>>()?;

    let client = reqwest::blocking::Client::builder()
        .timeout(req.timeout)
        .user_agent(crate::app().user_agent)
        .build()
        .map_err(|e| DegenError::Http(format!("failed to create HTTP client: {e}")))?;

    let mut builder = client.request(req.method.clone(), &req.url);
    for (k, v) in &req.headers {
        // reqwest writes its own Content-Type for a multipart body, boundary
        // included; the tool's value would make the body unparseable.
        if req.multipart.is_some() && k.eq_ignore_ascii_case("content-type") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(body) = &req.body {
        builder = builder.json(body);
    }
    if let Some(multipart) = &req.multipart {
        builder = builder.multipart(build_form(multipart, &tool.name)?);
    }

    // `without_url`: the real URL may carry a credential; errors print the display URL.
    let what = format!("{} {}", req.method, req.display_url);
    let response = builder
        .send()
        .map_err(|e| DegenError::Http(format!("{what} failed: {}", e.without_url())))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|e| DegenError::Http(format!("{what}: reading response failed: {}", e.without_url())))?;
    // Every return path below goes through here, so nothing that was actually
    // sent escapes the ledger.
    let finish = |ok: bool, error: Option<String>, response: Value, saved_media: Vec<String>, stored_secrets: Vec<StoredSecret>| {
        let outcome = Outcome {
            tool: tool.name.clone(),
            package: pkg.id().to_string(),
            ok,
            status: status.as_u16(),
            error,
            response,
            saved_media,
            stored_secrets,
            duration_ms: started.elapsed().as_millis(),
        };
        crate::app().policy.record(tool, &args, &ctx, &outcome);
        outcome
    };
    let Ok(mut data) = serde_json::from_str::<Value>(&text) else {
        let shown = Value::String(if saves.is_empty() { paths::redact_text(&text, &sensitive, &mask) } else { String::new() });
        if !status.is_success() {
            return Ok(finish(false, Some(format!("{what} returned HTTP {}", status.as_u16())), shown, vec![], vec![]));
        }
        if !saves.is_empty() {
            return Err(DegenError::InvalidArgs("--save-secret: the response is not JSON".to_string()));
        }
        return Ok(finish(true, None, shown, vec![], vec![]));
    };

    let failure = if !status.is_success() {
        Some(format!("{what} returned HTTP {}", status.as_u16()))
    } else {
        tool.error_path
            .as_deref()
            .filter(|p| paths::find(&data, p).iter().any(|(_, v)| paths::is_present(v)))
            .map(|p| format!("{what} returned errors (see `{p}` in the response)"))
    };

    // Secrets are stored before anything is printed, then masked in what is.
    let mut stored_names = Vec::new();
    if failure.is_none() {
        for (name, path) in &saves {
            let (at, place) = save_secret(&data, &tool, name, path.as_deref(), opts.global)?;
            stored_names.push(StoredSecret { name: name.clone(), from: at, stored_in: place });
        }
    }
    let secret_paths: Vec<&str> = tool
        .secret_paths
        .iter()
        .map(String::as_str)
        .chain(saves.iter().filter_map(|(_, p)| p.as_deref()))
        .collect();
    for path in &secret_paths {
        paths::replace_strings(&mut data, path, &mask);
    }
    paths::redact(&mut data, &sensitive, &mask);

    if let Some(failure) = failure {
        return Ok(finish(false, Some(failure), data, vec![], vec![]));
    }
    let mut saved = if tool.save.is_empty() {
        Vec::new()
    } else {
        save_media(&client, &media_urls(&data, &tool.save), &tool.name, opts.out.as_deref())?
    };
    if !tool.save_inline.is_empty() {
        saved.extend(save_inline(&mut data, &tool.save_inline, &tool.name, opts.out.as_deref())?);
    }
    Ok(finish(true, None, data, saved, stored_names))
}

/// Run a tool the binary implements, and report it like any other call.
fn run_native(
    pkg: &Package,
    tool: &ToolConfig,
    handler: &str,
    args: &Map<String, Value>,
    ctx: &crate::config::CallContext<'_>,
    started: std::time::Instant,
) -> Result<Outcome, DegenError> {
    // An installed package is someone else's JSON. Letting it name a handler
    // would let it run code this binary meant only for its own tools.
    if !pkg.is_bundled() {
        return Err(DegenError::InvalidPackage(format!(
            "{} is an installed package, so it may not use the native handler '{handler}'",
            pkg.id()
        )));
    }
    let native = crate::app()
        .natives
        .iter()
        .find(|n| n.id == handler)
        .ok_or_else(|| DegenError::InvalidPackage(format!("tool '{}' wants the native handler '{handler}', which this binary does not have", tool.name)))?;

    let (response, ok, error) = match (native.run)(args, ctx) {
        Ok(response) => (response, true, None),
        // A failure inside a multi-step tool is the tool's own failure, not a
        // transport error: it comes back as an outcome so the caller sees how
        // far it got.
        Err(e) => (Value::Null, false, Some(e.to_string())),
    };
    let outcome = Outcome {
        tool: tool.name.clone(),
        package: pkg.id().to_string(),
        ok,
        status: if ok { 200 } else { 0 },
        error,
        response,
        saved_media: Vec::new(),
        stored_secrets: Vec::new(),
        duration_ms: started.elapsed().as_millis(),
    };
    crate::app().policy.record(tool, args, ctx, &outcome);
    Ok(outcome)
}

/// The largest file a tool call will read off disk. An upload is a file this
/// machine publishes, so the limit is about what fits in memory and what any
/// of these APIs accept, not about trust.
const MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Read each named file and build the form. The path came from an argument, so
/// a missing or unreadable file is the caller's mistake and says so.
fn build_form(multipart: &Multipart, tool: &str) -> Result<reqwest::blocking::multipart::Form, DegenError> {
    let mut form = reqwest::blocking::multipart::Form::new();
    for (name, value) in &multipart.fields {
        form = form.text(name.clone(), value.clone());
    }
    for file in &multipart.files {
        let shown = file.path.display();
        let size = fs::metadata(&file.path)
            .map_err(|e| DegenError::InvalidArgs(format!("{tool}: cannot read {shown}: {e}")))?
            .len();
        if size > MAX_UPLOAD_BYTES {
            return Err(DegenError::InvalidArgs(format!(
                "{tool}: {shown} is {size} bytes, over the {MAX_UPLOAD_BYTES} byte upload limit"
            )));
        }
        let bytes = fs::read(&file.path).map_err(|e| DegenError::InvalidArgs(format!("{tool}: cannot read {shown}: {e}")))?;
        let name = file.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "upload".to_string());
        let ext = file.path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        let part = reqwest::blocking::multipart::Part::bytes(bytes)
            .file_name(name)
            .mime_str(mime_for(&ext))
            .map_err(|e| DegenError::InvalidArgs(format!("{tool}: {shown}: {e}")))?;
        form = form.part(file.field.clone(), part);
    }
    Ok(form)
}

/// The content type for a file extension. An API that checks the type of an
/// upload rejects `application/octet-stream`, so the common media types are
/// named rather than guessed at.
fn mime_for(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// How a secret looks in printed output.
fn mask(value: &str) -> String {
    if value.is_empty() { String::new() } else { format!("<secret: {} chars>", value.chars().count()) }
}

/// Split `A=B` flags.
fn pairs(raw: &[String], flag: &str, shape: &str) -> Result<Vec<(String, String)>, DegenError> {
    raw.iter()
        .map(|item| match item.split_once('=') {
            Some((a, b)) if !a.is_empty() && !b.is_empty() => Ok((a.to_string(), b.to_string())),
            _ => Err(DegenError::InvalidArgs(format!("{flag} expects {shape}, got '{item}'"))),
        })
        .collect()
}

/// `NAME` or `NAME=path`.
fn parse_save(raw: &str) -> Result<(String, Option<String>), DegenError> {
    let (name, path) = match raw.split_once('=') {
        Some((n, p)) => (n, Some(p.to_string())),
        None => (raw, None),
    };
    if !auth::valid_name(name) {
        return Err(DegenError::InvalidArgs(format!(
            "--save-secret {name}: credential names are letters, digits and underscores, like DD_DATABASE_URL"
        )));
    }
    Ok((name.to_string(), path))
}

/// Built-in packages may be handed any stored credential. A package installed
/// from elsewhere is someone else's code, so it only gets the credentials it
/// declared; otherwise `--secret prompt=RAILWAY_API_TOKEN` would send a Railway
/// token to whatever host that package names.
fn may_receive(pkg: &Package, credential: &str) -> Result<(), DegenError> {
    if pkg.is_bundled() || pkg.integration.requires_env.iter().any(|v| v == credential) {
        return Ok(());
    }
    Err(DegenError::InvalidArgs(format!(
        "{} is an installed third-party package, so it may only use the credentials it declares ({}), not {credential}",
        pkg.id(),
        pkg.integration.requires_env.join(", ")
    )))
}

/// Store the one secret the response holds (at `path`, or at the tool's
/// `secret_paths`) as credential `name`. Returns the concrete path it came from.
fn save_secret(data: &Value, tool: &ToolConfig, name: &str, path: Option<&str>, global: bool) -> Result<(String, String), DegenError> {
    let patterns: Vec<&str> = match path {
        Some(p) => vec![p],
        None if tool.secret_paths.is_empty() => {
            return Err(DegenError::InvalidArgs(format!(
                "--save-secret {name}: {} declares no secret fields; name one with --save-secret {name}=<path>",
                tool.name
            )));
        }
        None => tool.secret_paths.iter().map(String::as_str).collect(),
    };
    let mut found: Vec<(String, String)> = Vec::new();
    for pattern in patterns {
        for (at, value) in paths::find(data, pattern) {
            if let Some(v) = value.as_str().filter(|v| !v.is_empty())
                && !found.iter().any(|(_, seen)| seen == v)
            {
                found.push((at, v.to_string()));
            }
        }
    }
    match found.as_slice() {
        [(at, value)] => {
            let place = auth::store(name, value, global)?;
            Ok((at.clone(), place))
        }
        [] => Err(DegenError::InvalidArgs(format!(
            "--save-secret {name}: the response has no secret {}",
            path.map(|p| format!("at {p}")).unwrap_or_else(|| "in the tool's secret fields".to_string())
        ))),
        many => Err(DegenError::InvalidArgs(format!(
            "--save-secret {name}: the response holds {} different secrets; pick one with --save-secret {name}=<path>:\n  {}",
            many.len(),
            many.iter().map(|(at, _)| at.as_str()).collect::<Vec<_>>().join("\n  ")
        ))),
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn print_text(text: &str) {
    if text.ends_with('\n') {
        print!("{text}");
    } else {
        println!("{text}");
    }
}

fn media_urls(data: &Value, paths: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for path in paths {
        for (_, value) in paths::find(data, path) {
            let Some(url) = value.as_str() else { continue };
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                eprintln!("note: not downloading {path} (not an http URL)");
                continue;
            }
            if !urls.iter().any(|u| u == url) {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

/// Write every string found at a `save_inline` path to its own file, then
/// replace it in the response with a note naming the file. Returns the paths.
fn save_inline(data: &mut Value, specs: &[InlineSave], tool: &str, out: Option<&Path>) -> Result<Vec<String>, DegenError> {
    let mut found: Vec<(String, String)> = Vec::new(); // (content, ext)
    for spec in specs {
        if !spec.valid_ext() {
            return Err(DegenError::InvalidArgs(format!("{tool}: save_inline extension '{}' is not a plain file extension", spec.ext)));
        }
        for (_, value) in paths::find(data, &spec.path) {
            if let Some(text) = value.as_str().filter(|t| !t.is_empty()) {
                found.push((text.to_string(), spec.ext.clone()));
            }
        }
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut written: HashMap<String, String> = HashMap::new();
    let mut saved = Vec::new();
    for (i, (content, ext)) in found.iter().enumerate() {
        let path = destination(out, tool, i, found.len(), ext, stamp);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, content)?;
        let shown = path.display().to_string();
        written.insert(content.clone(), shown.clone());
        saved.push(shown);
    }
    for spec in specs {
        paths::replace_strings(data, &spec.path, &|s: &str| match written.get(s) {
            Some(file) => format!("<saved to {file}: {} chars>", s.chars().count()),
            None => s.to_string(),
        });
    }
    Ok(saved)
}

/// Download each URL — with no credentials attached — and return the local paths.
fn save_media(
    client: &reqwest::blocking::Client,
    urls: &[String],
    tool: &str,
    out: Option<&Path>,
) -> Result<Vec<String>, DegenError> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut saved = Vec::new();
    for (i, url) in urls.iter().enumerate() {
        let response = client
            .get(url)
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| DegenError::Http(format!("downloading {url} failed: {e}")))?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = response
            .bytes()
            .map_err(|e| DegenError::Http(format!("downloading {url} failed: {e}")))?;
        let ext = extension_for(content_type.as_deref(), url);
        let path = destination(out, tool, i, urls.len(), &ext, stamp);
        if let Some(asked) = out.and_then(Path::extension)
            && path.extension() != Some(asked)
        {
            eprintln!(
                "note: saved as .{ext}, not .{} — the server sent {}",
                asked.to_string_lossy(),
                content_type.as_deref().unwrap_or("that format")
            );
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &bytes)?;
        saved.push(path.display().to_string());
    }
    Ok(saved)
}

fn extension_for(content_type: Option<&str>, url: &str) -> String {
    let by_type = content_type
        .map(|ct| ct.split(';').next().unwrap_or("").trim())
        .and_then(|ct| match ct {
            "image/png" => Some("png"),
            "image/jpeg" | "image/jpg" => Some("jpg"),
            "image/webp" => Some("webp"),
            "image/gif" => Some("gif"),
            "image/svg+xml" => Some("svg"),
            "video/mp4" => Some("mp4"),
            "video/webm" => Some("webm"),
            "audio/mpeg" => Some("mp3"),
            "audio/wav" | "audio/x-wav" => Some("wav"),
            _ => None,
        });
    if let Some(ext) = by_type {
        return ext.to_string();
    }
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty() && ext.len() <= 5 && ext.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "bin".to_string())
}

/// Where file `index` of `count` goes. `--out` may name a directory (existing,
/// or written with a trailing `/`) or a file; a file name gets `-1`, `-2`, ...
/// when there is more than one. A file name keeps its extension only when it
/// matches what the server sent — `hero.png` holding JPEG bytes is a lie that
/// breaks whatever reads it next — so a known mismatch takes the real one.
fn destination(out: Option<&Path>, tool: &str, index: usize, count: usize, ext: &str, stamp: u64) -> PathBuf {
    let numbered = |stem: &str| {
        if count > 1 { format!("{stem}-{}", index + 1) } else { stem.to_string() }
    };
    let generated = format!("{}.{ext}", numbered(&format!("{tool}-{stamp}")));
    match out {
        None => PathBuf::from(generated),
        Some(p) if p.is_dir() || p.to_string_lossy().ends_with('/') => p.join(generated),
        Some(p) => {
            let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| tool.to_string());
            let given = p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
            let ext = match given {
                Some(g) if ext == "bin" || g == ext || (g == "jpeg" && ext == "jpg") => g,
                _ => ext.to_string(),
            };
            p.with_file_name(format!("{}.{ext}", numbered(&stem)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_urls_follow_save_paths() {
        let data = json!({
            "images": [{"url": "https://v3.fal.media/a.jpg"}, {"url": "https://v3.fal.media/b.jpg"}, {"url": "data:image/png;base64,xx"}],
            "video": {"url": "https://v3.fal.media/c.mp4"}
        });
        let paths = vec!["images[].url".to_string(), "image.url".to_string(), "video.url".to_string()];
        assert_eq!(
            media_urls(&data, &paths),
            vec!["https://v3.fal.media/a.jpg", "https://v3.fal.media/b.jpg", "https://v3.fal.media/c.mp4"]
        );
    }

    #[test]
    fn inline_content_is_written_and_replaced() {
        let dir = std::env::temp_dir().join(format!("dt-inline-{}", std::process::id()));
        let mut data = json!({"data": [{"svg": "<svg>a</svg>", "mime_type": "image/svg+xml"}, {"svg": "<svg>bb</svg>"}]});
        let specs = vec![InlineSave { path: "data[].svg".into(), ext: "svg".into() }];
        let out = dir.join("logo.svg");
        let saved = save_inline(&mut data, &specs, "quiver_generate_svg", Some(&out)).unwrap();
        assert_eq!(saved.len(), 2);
        assert_eq!(fs::read_to_string(&saved[0]).unwrap(), "<svg>a</svg>");
        assert_eq!(fs::read_to_string(&saved[1]).unwrap(), "<svg>bb</svg>");
        assert!(saved[0].ends_with("logo-1.svg") && saved[1].ends_with("logo-2.svg"));
        assert_eq!(data["data"][0]["svg"], json!(format!("<saved to {}: 12 chars>", saved[0])));
        assert_eq!(data["data"][0]["mime_type"], json!("image/svg+xml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inline_extension_must_be_plain() {
        let mut data = json!({"svg": "<svg/>"});
        let specs = vec![InlineSave { path: "svg".into(), ext: "../x".into() }];
        assert!(save_inline(&mut data, &specs, "t", None).is_err());
    }

    #[test]
    fn destinations() {
        assert_eq!(destination(None, "t", 0, 1, "jpg", 9), PathBuf::from("t-9.jpg"));
        assert_eq!(destination(Some(Path::new("hero.png")), "t", 0, 1, "png", 9), PathBuf::from("hero.png"));
        assert_eq!(destination(Some(Path::new("hero.png")), "t", 0, 1, "jpg", 9), PathBuf::from("hero.jpg"));
        assert_eq!(destination(Some(Path::new("hero.jpeg")), "t", 0, 1, "jpg", 9), PathBuf::from("hero.jpeg"));
        assert_eq!(destination(Some(Path::new("hero.png")), "t", 0, 1, "bin", 9), PathBuf::from("hero.png"));
        assert_eq!(destination(Some(Path::new("art/hero")), "t", 1, 2, "jpg", 9), PathBuf::from("art/hero-2.jpg"));
        assert_eq!(destination(Some(Path::new("art/")), "t", 0, 2, "png", 9), PathBuf::from("art/t-9-1.png"));
    }

    #[test]
    fn extensions() {
        assert_eq!(extension_for(Some("image/png"), "https://x/y"), "png");
        assert_eq!(extension_for(Some("application/octet-stream"), "https://x/y/file.WEBP?sig=1"), "webp");
        assert_eq!(extension_for(None, "https://x/y/noext"), "bin");
    }
}
