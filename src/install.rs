use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use include_dir::{Dir, DirEntry};
use serde_json::Value;

use crate::config::{load_credentials, load_registries, lookup_credential, packages_dir};
use crate::errors::DegenError;
use crate::package::{Integration, valid_id};
use crate::tool::{SUPPORTED_BODY_MAPPINGS, ToolConfig, host_of};

/// Zip-bomb guard, matching the agent pack format's `MAX_BUNDLE_BYTES`.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Archive path → bytes.
type Files = BTreeMap<String, Vec<u8>>;

fn invalid(msg: impl Into<String>) -> DegenError {
    DegenError::InvalidPackage(msg.into())
}

/// `degen-tools install <source>`.
pub fn install(spec: &str, registry: Option<&str>) -> Result<(), DegenError> {
    let (files, source) = fetch(spec, registry)?;
    let staged = stage(&files)?;
    let creds = load_credentials()?;
    for pkg in &staged {
        write_package(pkg, &source)?;
        report(pkg, &source, &creds);
    }
    Ok(())
}

/// A local path is anything that looks like one; a bare id is a bundled package
/// first, then the registry. Registries are only consulted one at a time — the
/// default, or the one named — so an id is never resolved by silent first match.
fn fetch(spec: &str, registry: Option<&str>) -> Result<(Files, String), DegenError> {
    let looks_like_path = spec.contains('/')
        || spec.starts_with('.')
        || spec.starts_with('~')
        || spec.ends_with(".agentpack")
        || spec.ends_with(".zip");
    if registry.is_none() && looks_like_path {
        let path = Path::new(spec);
        if path.is_dir() {
            return Ok((read_dir_files(path)?, format!("path:{spec}")));
        }
        if path.is_file() {
            return Ok((read_zip(&fs::read(path)?)?, format!("file:{spec}")));
        }
        return Err(invalid(format!("{spec}: no such file or directory")));
    }
    if registry.is_none()
        && valid_id(spec)
        && let Some(dir) = crate::app().bundled.get_dir(spec)
    {
        let mut files = Files::new();
        collect_bundled(dir, dir.path(), &mut files);
        return Ok((files, "bundled".to_string()));
    }
    let (name, base, id) = resolve_registry(spec, registry)?;
    let bytes = registry_download(&base, &id)?;
    Ok((read_zip(&bytes)?, format!("registry:{name}:{id}")))
}

fn collect_bundled(dir: &Dir<'static>, root: &Path, files: &mut Files) {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(d) => collect_bundled(d, root, files),
            DirEntry::File(f) => {
                if let Ok(rel) = f.path().strip_prefix(root) {
                    files.insert(rel.to_string_lossy().replace('\\', "/"), f.contents().to_vec());
                }
            }
        }
    }
}

/// Every package compiled into the binary passes the validation an install
/// would apply. A binary asserts this over its own `bundled` directory, so a
/// malformed first-party package is caught where the packages live.
pub fn validate_bundled(bundled: &'static Dir<'static>) -> Result<(), DegenError> {
    for entry in bundled.dirs() {
        let id = entry.path().file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        let mut files = Files::new();
        collect_bundled(entry, entry.path(), &mut files);
        let staged = stage(&files).map_err(|e| invalid(format!("bundled {id}: {e}")))?;
        match staged.as_slice() {
            [pkg] if pkg.integration.id != id => {
                return Err(invalid(format!("bundled {id}: integration.json calls it '{}'", pkg.integration.id)));
            }
            [pkg] if pkg.tools.is_empty() => return Err(invalid(format!("bundled {id}: no tools"))),
            [_] => {}
            many => return Err(invalid(format!("bundled {id}: {} packages in one directory", many.len()))),
        }
    }
    Ok(())
}

fn read_dir_files(root: &Path) -> Result<Files, DegenError> {
    fn walk(dir: &Path, root: &Path, files: &mut Files, total: &mut u64) -> Result<(), DegenError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(&path, root, files, total)?;
            } else if kind.is_file() {
                let bytes = fs::read(&path)?;
                *total += bytes.len() as u64;
                if *total > MAX_BUNDLE_BYTES {
                    return Err(invalid("package directory exceeds the maximum allowed size"));
                }
                let rel = path.strip_prefix(root).map_err(|_| invalid("path escaped package root"))?;
                files.insert(rel.to_string_lossy().replace('\\', "/"), bytes);
            }
        }
        Ok(())
    }
    let mut files = Files::new();
    walk(root, root, &mut files, &mut 0)?;
    Ok(files)
}

/// Rejects `..`, absolute paths and drive letters, before anything is interpreted.
fn is_safe_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains(':')
        && !p.contains('\0')
        && !p.split('/').any(|seg| seg == "..")
}

/// Read a zip (`.agentpack`) fully into memory. The size budget is spent against
/// bytes actually read — the size an entry declares is whatever its builder wrote.
fn read_zip(bytes: &[u8]) -> Result<Files, DegenError> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| invalid(format!("not a valid package archive (zip): {e}")))?;
    let mut files = Files::new();
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| invalid(format!("reading zip entry: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        let raw = entry.name().replace('\\', "/");
        if !is_safe_path(&raw) || entry.is_symlink() {
            return Err(invalid(format!("unsafe path in archive: {}", entry.name())));
        }
        let remaining = MAX_BUNDLE_BYTES.saturating_sub(total);
        let mut buf = Vec::new();
        (&mut entry)
            .take(remaining + 1)
            .read_to_end(&mut buf)
            .map_err(|e| invalid(format!("reading {raw}: {e}")))?;
        if buf.len() as u64 > remaining {
            return Err(invalid("archive exceeds the maximum allowed size"));
        }
        total += buf.len() as u64;
        files.insert(raw, buf);
    }
    Ok(files)
}

/// A validated package, not yet on disk.
struct Staged {
    integration: Integration,
    tools: Vec<ToolConfig>,
    files: Files,
}

/// Find the packages in a file set: a bare integration (`integration.json` at the
/// root), or an agent pack, whose every `integrations/<id>/` becomes a package
/// carrying the pack's skills. Personas and presets are agent-only and dropped.
fn stage(files: &Files) -> Result<Vec<Staged>, DegenError> {
    if files.contains_key("integration.json") {
        return Ok(vec![stage_one(files.clone())?]);
    }
    if !files.contains_key("agent_pack.json") {
        return Err(invalid("no integration.json or agent_pack.json at the top level"));
    }
    let ids: BTreeSet<&str> = files
        .keys()
        .filter_map(|k| k.strip_prefix("integrations/")?.strip_suffix("/integration.json"))
        .filter(|id| !id.contains('/'))
        .collect();
    if ids.is_empty() {
        return Err(invalid(
            format!("this agent pack has no integrations, so it has no tools {} can run (it is a persona/skill-only pack)", crate::app().name),
        ));
    }
    let pack_skills: Vec<(&String, &Vec<u8>)> =
        files.iter().filter(|(k, _)| k.starts_with("skills/") && k.ends_with(".md")).collect();

    ids.into_iter()
        .map(|id| {
            let prefix = format!("integrations/{id}/");
            let mut sub: Files = files
                .iter()
                .filter_map(|(k, v)| Some((k.strip_prefix(&prefix)?.to_string(), v.clone())))
                .collect();
            for (k, v) in &pack_skills {
                sub.entry(k.to_string()).or_insert_with(|| v.to_vec());
            }
            let staged = stage_one(sub)?;
            if staged.integration.id != id {
                return Err(invalid(format!(
                    "integrations/{id}/ holds an integration whose id is '{}'",
                    staged.integration.id
                )));
            }
            Ok(staged)
        })
        .collect()
}

fn stage_one(files: Files) -> Result<Staged, DegenError> {
    let integration: Integration = serde_json::from_slice(&files["integration.json"])
        .map_err(|e| invalid(format!("integration.json: {e}")))?;
    if !valid_id(&integration.id) {
        return Err(invalid(format!("invalid package id '{}'", integration.id)));
    }

    // Keep only what degen-tools uses; nothing else from a stranger's archive lands on disk.
    let files: Files = files
        .into_iter()
        .filter(|(k, _)| {
            let one_level = |dir: &str, ext: &str| {
                k.strip_prefix(dir).is_some_and(|rest| !rest.contains('/') && rest.ends_with(ext))
            };
            k == "integration.json" || k == "README.md" || one_level("api_tools/", ".json") || one_level("skills/", ".md")
        })
        .collect();

    let mut tools = Vec::new();
    for (path, bytes) in files.iter().filter(|(k, _)| k.starts_with("api_tools/")) {
        let tool: ToolConfig =
            serde_json::from_slice(bytes).map_err(|e| invalid(format!("{path}: {e}")))?;
        let stem = path.trim_start_matches("api_tools/").trim_end_matches(".json");
        if tool.name != stem {
            return Err(invalid(format!("{path} declares a tool named '{}'", tool.name)));
        }
        if !SUPPORTED_BODY_MAPPINGS.contains(&tool.body_mapping.as_str()) {
            eprintln!(
                "warning: {} uses body_mapping \"{}\" and will not run under {}",
                tool.name, tool.body_mapping, crate::app().name
            );
        }
        let text = std::iter::once(tool.url.as_str()).chain(tool.headers.values().map(String::as_str));
        for var in text.flat_map(env_refs) {
            if !integration.requires_env.iter().any(|r| r == var) && var.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                eprintln!(
                    "warning: {} references ${var}, which integration.json does not declare in \
                     requires_env — {} will not fill it in",
                    tool.name,
                    crate::app().name
                );
            }
        }
        tools.push(tool);
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Staged { integration, tools, files })
}

fn env_refs(s: &str) -> Vec<&str> {
    s.split('$')
        .skip(1)
        .map(|rest| {
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// New files are written beside the old install and swapped in with renames, so
/// a failed install leaves the previous version intact.
fn write_package(pkg: &Staged, source: &str) -> Result<(), DegenError> {
    let root = packages_dir()?;
    let id = &pkg.integration.id;
    let final_dir = root.join(id);
    let tmp = root.join(format!(".{id}.installing"));
    let old = root.join(format!(".{id}.old"));
    for stale in [&tmp, &old] {
        if stale.exists() {
            fs::remove_dir_all(stale)?;
        }
    }

    for (rel, bytes) in &pkg.files {
        let path = tmp.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
    }
    let installed_at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let meta = serde_json::json!({
        "source": source,
        "version": pkg.integration.version,
        "installed_at": installed_at,
    });
    fs::write(tmp.join(".source.json"), serde_json::to_vec_pretty(&meta)?)?;

    if final_dir.exists() {
        fs::rename(&final_dir, &old)?;
    }
    fs::rename(&tmp, &final_dir)?;
    if old.exists() {
        fs::remove_dir_all(&old)?;
    }
    Ok(())
}

fn report(pkg: &Staged, source: &str, creds: &crate::config::Credentials) {
    let i = &pkg.integration;
    println!("✓ Installed {} {} ({} tools) from {source}", i.id, i.version, pkg.tools.len());
    let hosts: BTreeSet<String> = pkg.tools.iter().filter_map(|t| host_of(&t.url)).collect();
    if !hosts.is_empty() {
        println!("  talks to:  {}", hosts.into_iter().collect::<Vec<_>>().join(", "));
    }
    for var in &i.requires_env {
        if lookup_credential(creds, var).is_some() {
            println!("  needs:     {var} (set)");
        } else {
            println!("  needs:     {var} — not set: {} auth set {var}", crate::app().name);
        }
    }
    let names: Vec<&str> = pkg.tools.iter().map(|t| t.name.as_str()).collect();
    println!("  tools:     {}", names.join(", "));
    println!("  docs:      {} skill {}", crate::app().name, i.id);
}

pub fn remove(id: &str) -> Result<(), DegenError> {
    let dir = packages_dir()?.join(id);
    if !valid_id(id) || !dir.join("integration.json").is_file() {
        return Err(DegenError::PackageNotFound(id.to_string()));
    }
    fs::remove_dir_all(&dir)?;
    println!("✓ Removed {id}");
    Ok(())
}

/// `registry:@handle`, `@handle` or `handle`, with `--registry` naming a
/// configured registry or giving a URL outright.
fn resolve_registry(spec: &str, flag: Option<&str>) -> Result<(String, String, String), DegenError> {
    let regs = load_registries()?;
    let (named, id) = match spec.split_once(':') {
        Some((r, id)) if regs.registries.contains_key(r) => (Some(r), id),
        _ => (None, spec),
    };
    let id = id.trim_start_matches('@');
    if !valid_id(id) {
        return Err(invalid(format!("'{spec}' is not a package id, a registry reference, or a path")));
    }
    let registry = flag.or(named).unwrap_or(&regs.default);
    let (name, url) = if registry.starts_with("https://") || registry.starts_with("http://") {
        (registry.to_string(), registry.to_string())
    } else {
        let entry = regs
            .registries
            .get(registry)
            .ok_or_else(|| invalid(format!("no registry named '{registry}' in ~/{}/registries.json", crate::app().dir)))?;
        (registry.to_string(), entry.url.clone())
    };
    Ok((name, url.trim_end_matches('/').to_string(), id.to_string()))
}

/// Registries get no redirects: a redirect is how an allowed origin is used to
/// reach one that isn't.
fn registry_client() -> Result<reqwest::blocking::Client, DegenError> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(crate::app().user_agent)
        .build()
        .map_err(|e| DegenError::Http(format!("failed to create HTTP client: {e}")))
}

fn registry_download(base: &str, id: &str) -> Result<Vec<u8>, DegenError> {
    let url = format!("{base}/api/v1/agent-packs/{id}/download");
    let response = registry_client()?
        .get(&url)
        .send()
        .map_err(|e| DegenError::Http(format!("GET {url} failed: {e}")))?;
    match response.status().as_u16() {
        200 => {}
        404 => return Err(DegenError::PackageNotFound(id.to_string())),
        code => return Err(DegenError::Http(format!("GET {url} returned HTTP {code}"))),
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| DegenError::Http(format!("GET {url}: {e}")))?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(invalid("download exceeds the maximum allowed size"));
    }
    Ok(bytes)
}

/// `degen-tools search <query>`.
pub fn search(query: &str, registry: Option<&str>) -> Result<(), DegenError> {
    let (name, base, _) = resolve_registry("x", registry)?;
    let url = format!("{base}/api/v1/agent-packs/search");
    let response = registry_client()?
        .get(&url)
        .query(&[("q", query), ("limit", "20")])
        .send()
        .map_err(|e| DegenError::Http(format!("GET {url} failed: {e}")))?;
    if !response.status().is_success() {
        return Err(DegenError::Http(format!("GET {url} returned HTTP {}", response.status().as_u16())));
    }
    let body: Value = response
        .json()
        .map_err(|e| DegenError::Http(format!("{url}: unreadable response: {e}")))?;
    let results = body["results"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        println!("No packages match '{query}' on {name}.");
        return Ok(());
    }
    println!("  {:<24} {:<9} NAME", "PACKAGE", "VERSION");
    println!("  {}", "-".repeat(70));
    for r in &results {
        let handle = r["handle"].as_str().or(r["slug"].as_str()).unwrap_or("?");
        let label = r["tagline"].as_str().filter(|t| !t.is_empty()).or(r["name"].as_str()).unwrap_or("");
        println!("  {:<24} {:<9} {}", handle, r["version"].as_str().unwrap_or(""), label);
    }
    println!("\nInstall: {} install <package>   (from {name})", crate::app().name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, body) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap();
        buf.into_inner()
    }

    const TOOL: &str = r#"{"name": "demo_ping", "method": "GET", "url": "https://demo.example/ping", "body_mapping": "none"}"#;

    #[test]
    fn unsafe_archive_paths_are_rejected() {
        for bad in ["../evil.json", "/abs.json", "C:/x.json", "a/../../b"] {
            assert!(!is_safe_path(bad), "{bad}");
        }
        let archive = zip_of(&[("integration.json", "{}"), ("../escape.json", "{}")]);
        assert!(read_zip(&archive).is_err());
    }

    #[test]
    fn an_agent_pack_becomes_one_package_per_integration() {
        let archive = zip_of(&[
            ("agent_pack.json", r#"{"id": "demo-pack"}"#),
            ("personas/p.json", "{}"),
            ("skills/demo.md", "# demo"),
            ("integrations/demo/integration.json", r#"{"id": "demo", "version": "1.0.0", "requires_env": []}"#),
            ("integrations/demo/api_tools/demo_ping.json", TOOL),
        ]);
        let staged = stage(&read_zip(&archive).unwrap()).unwrap();
        assert_eq!(staged.len(), 1);
        let keys: Vec<&str> = staged[0].files.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["api_tools/demo_ping.json", "integration.json", "skills/demo.md"]);
    }

    #[test]
    fn a_tool_file_must_be_named_for_its_tool() {
        let mut files = Files::new();
        files.insert("integration.json".into(), br#"{"id": "demo"}"#.to_vec());
        files.insert("api_tools/other.json".into(), TOOL.as_bytes().to_vec());
        assert!(stage(&files).is_err());
    }
}
