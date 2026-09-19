//! The same tools over a loopback HTTP API, so an agent (or any local program)
//! can call them with JSON instead of a shell.
//!
//! The server is a door to every stored credential, so it is locked three ways:
//! - it listens on 127.0.0.1 only;
//! - every call except `/health` needs the session's bearer token, a fresh
//!   random value per run, written to an owner-only file for `connect`;
//! - it refuses requests carrying a browser `Origin` header or a `Host` other
//!   than its own address, so a web page can't reach it (no CORS, and DNS
//!   rebinding sees a wrong Host).
//!
//! A binary adds its own routes through the `extra` router [`start`] takes, so
//! they sit inside the same lockdown rather than beside it.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::args;
use crate::config::{self, Source, data_dir, load_credentials, resolve_credential};
use crate::errors::DegenError;
use crate::package;
use crate::run::{self, RunOptions};
use crate::skill;

/// One line in the dashboard's request log.
pub struct LogEntry {
    pub at: SystemTime,
    pub method: String,
    pub path: String,
    pub tool: Option<String>,
    pub status: u16,
    pub ok: bool,
    pub duration_ms: u128,
    pub note: String,
}

/// What `connect` needs to reach a running server.
#[derive(Serialize, Deserialize, Clone)]
pub struct Connection {
    pub url: String,
    pub token: String,
    pub pid: u32,
    /// The directory the server was started in.
    pub cwd: String,
    /// The project `.env` it reads, if any.
    pub project_env: Option<String>,
    pub started_at: u64,
}

pub struct AppState {
    token: String,
    port: u16,
    log: Sender<LogEntry>,
}

pub type Shared = Arc<AppState>;

pub fn new_token() -> Result<String, DegenError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| DegenError::InvalidArgs(format!("no randomness available: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn servers_dir() -> Result<PathBuf, DegenError> {
    let dir = data_dir()?.join("servers");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Record a running server for `connect`, owner-only.
pub fn register(conn: &Connection, port: u16) -> Result<PathBuf, DegenError> {
    let path = servers_dir()?.join(format!("{port}.json"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    std::io::Write::write_all(&mut file, serde_json::to_string_pretty(conn)?.as_bytes())?;
    Ok(path)
}

/// For a binary that adds no routes of its own.
pub fn no_routes() -> Router<Shared> {
    Router::new()
}

/// Bind and serve until the process exits, with `extra` merged inside the token
/// and same-machine checks. Returns the bound address once listening, with the
/// server running on the given runtime.
pub async fn start(port: u16, token: String, log: Sender<LogEntry>, extra: Router<Shared>) -> Result<SocketAddr, DegenError> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| DegenError::InvalidArgs(format!("could not listen on 127.0.0.1:{port}: {e}")))?;
    let addr = listener.local_addr()?;
    let state: Shared = Arc::new(AppState { token, port: addr.port(), log });

    let api = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/packages", get(packages))
        .route("/v1/packages/{id}", get(package_detail))
        .route("/v1/tools/{name}", get(tool_detail))
        .route("/v1/run", post(run_tool))
        .merge(extra)
        .layer(middleware::from_fn_with_state(state.clone(), require_token));
    let app = Router::new()
        .route("/health", get(health))
        .merge(api)
        .layer(middleware::from_fn_with_state(state.clone(), same_machine_only))
        .with_state(state);

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

fn problem(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

/// No browsers, and only our own address in `Host`.
async fn same_machine_only(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h == format!("127.0.0.1:{}", state.port) || h == format!("localhost:{}", state.port));
    let refused = if headers.contains_key(header::ORIGIN) {
        Some("requests from web pages are not accepted")
    } else if !host_ok {
        Some("wrong Host header; call http://127.0.0.1:<port> directly")
    } else {
        None
    };
    let response = match refused {
        Some(why) => problem(StatusCode::FORBIDDEN, why),
        None => next.run(req).await,
    };
    if path != "/v1/run" {
        let status = response.status();
        let _ = state.log.send(LogEntry {
            at: SystemTime::now(),
            method,
            path,
            tool: None,
            status: status.as_u16(),
            ok: status.is_success(),
            duration_ms: started.elapsed().as_millis(),
            note: refused.unwrap_or("").to_string(),
        });
    }
    response
}

async fn require_token(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let given = bearer(req.headers());
    let ok = given.is_some_and(|t| constant_time_eq(t.as_bytes(), state.token.as_bytes()));
    if !ok {
        return problem(
            StatusCode::UNAUTHORIZED,
            format!("missing or wrong token: send Authorization: Bearer <token> (get it with `{} connect`)", crate::app().name),
        );
    }
    next.run(req).await
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "name": crate::app().name, "version": crate::app().version }))
}

fn source_label(source: &Source) -> Value {
    match source {
        Source::Project(p) => json!({ "kind": "project", "path": p.display().to_string() }),
        Source::Global => json!({ "kind": "global" }),
        Source::Environment => json!({ "kind": "environment" }),
    }
}

/// Everything an agent needs to orient itself. Values are never included.
async fn status() -> Response {
    blocking(|| {
        let creds = load_credentials()?;
        let mut names: Vec<String> = creds.keys.keys().cloned().collect();
        if let Some(p) = &creds.project {
            names.extend(p.vars.keys().cloned());
        }
        names.sort();
        names.dedup();
        let credentials: Vec<Value> = names
            .iter()
            .filter_map(|n| resolve_credential(&creds, n).map(|(v, s)| json!({ "name": n, "chars": v.chars().count(), "source": source_label(&s) })))
            .collect();
        Ok(json!({
            "version": crate::app().version,
            "cwd": std::env::current_dir().ok().map(|d| d.display().to_string()),
            "project_env": creds.project.as_ref().filter(|p| p.path.is_file()).map(|p| p.path.display().to_string()),
            "credentials": credentials,
            "packages": package_summaries(&creds)?,
            "api": {
                "run": "POST /v1/run {tool, args, secrets: {param: CREDENTIAL}, save_secrets: {NAME: path|null}, cred: {VAR: CREDENTIAL}, global}",
                "package": "GET /v1/packages/{id} (guide + every tool's schema)",
                "tool": "GET /v1/tools/{name}"
            }
        }))
    })
    .await
}

fn package_summaries(creds: &config::Credentials) -> Result<Vec<Value>, DegenError> {
    Ok(package::available()?
        .iter()
        .map(|p| {
            json!({
                "id": p.id(),
                "name": p.integration.name,
                "version": p.integration.version,
                "built_in": p.is_bundled(),
                "tools": p.tools().map(|t| t.len()).unwrap_or(0),
                "keys": p.integration.requires_env.iter().map(|k| json!({ "name": k, "set": config::lookup_credential(creds, k).is_some() })).collect::<Vec<_>>(),
            })
        })
        .collect())
}

async fn packages() -> Response {
    blocking(|| Ok(json!({ "packages": package_summaries(&load_credentials()?)? }))).await
}

fn tool_json(t: &crate::tool::ToolConfig) -> Value {
    json!({
        "name": t.name,
        "description": t.description,
        "method": t.method,
        "parameters": t.parameters,
        "secret_paths": t.secret_paths,
        "saves_media": !t.save.is_empty() || !t.save_inline.is_empty(),
    })
}

async fn package_detail(Path(id): Path<String>) -> Response {
    blocking(move || {
        let pkg = package::find(&id)?;
        Ok(json!({
            "id": pkg.id(),
            "name": pkg.integration.name,
            "description": pkg.integration.description,
            "requires_env": pkg.integration.requires_env,
            "guide": skill::package_guide(&pkg),
            "tools": pkg.tools()?.iter().map(tool_json).collect::<Vec<_>>(),
        }))
    })
    .await
}

async fn tool_detail(Path(name): Path<String>) -> Response {
    blocking(move || {
        let (pkg, tool) = package::find_tool(&name)?;
        let mut v = tool_json(&tool);
        v["package"] = json!(pkg.id());
        Ok(v)
    })
    .await
}

#[derive(Deserialize)]
struct RunRequest {
    tool: String,
    #[serde(default)]
    args: Map<String, Value>,
    /// parameter → credential name
    #[serde(default)]
    secrets: BTreeMap<String, String>,
    /// credential name → response path (null: the tool's own secret fields)
    #[serde(default)]
    save_secrets: BTreeMap<String, Option<String>>,
    /// package variable → credential name
    #[serde(default)]
    cred: BTreeMap<String, String>,
    #[serde(default)]
    global: bool,
    #[serde(default)]
    out: Option<String>,
    /// Act as this connected account (`x:handle`).
    #[serde(default)]
    account: Option<String>,
}

async fn run_tool(State(state): State<Shared>, Json(req): Json<RunRequest>) -> Response {
    let started = Instant::now();
    let tool_name = req.tool.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<run::Outcome, DegenError> {
        let (pkg, tool) = package::find_tool(&req.tool)?;
        args::check_known(&tool, &req.args)?;
        let opts = RunOptions {
            out: req.out.map(PathBuf::from),
            json: None,
            secrets: req.secrets.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
            save_secrets: req.save_secrets.into_iter().map(|(k, v)| v.map_or(k.clone(), |p| format!("{k}={p}"))).collect(),
            creds: req.cred.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
            global: req.global,
            account: req.account,
        };
        run::execute(&pkg, &tool, req.args, &opts)
    })
    .await;

    let (response, status, ok, note) = match result {
        Ok(Ok(outcome)) => {
            let note = outcome.error.clone().unwrap_or_else(|| format!("HTTP {}", outcome.status));
            let ok = outcome.ok;
            (Json(json!(outcome)).into_response(), StatusCode::OK, ok, note)
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            (problem(StatusCode::BAD_REQUEST, &msg), StatusCode::BAD_REQUEST, false, first_line(&msg))
        }
        Err(e) => (problem(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()), StatusCode::INTERNAL_SERVER_ERROR, false, "crashed".into()),
    };
    let _ = state.log.send(LogEntry {
        at: SystemTime::now(),
        method: "POST".into(),
        path: "/v1/run".into(),
        tool: Some(tool_name),
        status: status.as_u16(),
        ok,
        duration_ms: started.elapsed().as_millis(),
        note,
    });
    response
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

async fn blocking<F>(f: F) -> Response
where
    F: FnOnce() -> Result<Value, DegenError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e @ (DegenError::PackageNotFound(_) | DegenError::ToolNotFound(_)))) => problem(StatusCode::NOT_FOUND, e.to_string()),
        Ok(Err(e)) => problem(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e) => problem(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `connect`: how to reach the server started for this directory.
pub fn connect() -> Result<(), DegenError> {
    let cwd = std::env::current_dir()?.display().to_string();
    let project = crate::project::current().filter(|p| p.path.is_file()).map(|p| p.path.display().to_string());
    let mut live: Vec<Connection> = Vec::new();
    for entry in fs::read_dir(servers_dir()?)? {
        let path = entry?.path();
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let Ok(conn) = serde_json::from_str::<Connection>(&text) else { continue };
        let alive = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(800))
            .build()
            .ok()
            .and_then(|c| c.get(format!("{}/health", conn.url)).send().ok())
            .is_some_and(|r| r.status().is_success());
        if alive {
            live.push(conn);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    let chosen = live
        .iter()
        .find(|c| project.is_some() && c.project_env == project)
        .or_else(|| live.iter().find(|c| c.cwd == cwd))
        .or_else(|| if live.len() == 1 { live.first() } else { None });
    let app = crate::app();
    let Some(conn) = chosen else {
        return Err(DegenError::InvalidArgs(if live.is_empty() {
            format!("no {0} server is running. Start one with `{0} serve` in the project directory", app.name)
        } else {
            format!(
                "{} servers are running and none belongs to this directory:\n  {}",
                live.len(),
                live.iter().map(|c| format!("{}  ({})", c.url, c.cwd)).collect::<Vec<_>>().join("\n  ")
            )
        }));
    };
    let (url, token) = (format!("{}_URL", app.env_prefix), format!("{}_TOKEN", app.env_prefix));
    println!("{url}={}", conn.url);
    println!("{token}={}", conn.token);
    eprintln!("\n# example:");
    eprintln!("#   curl -s ${url}/v1/status -H \"Authorization: Bearer ${token}\"");
    eprintln!(
        "#   curl -s ${url}/v1/run -H \"Authorization: Bearer ${token}\" -H 'Content-Type: application/json' \\\n#     -d '{{\"tool\":\"{}\",\"args\":{{}}}}'",
        app.example_tool
    );
    Ok(())
}
