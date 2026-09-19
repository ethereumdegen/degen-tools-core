use std::fs;
use std::path::{Path, PathBuf};

use include_dir::Dir;
use serde::Deserialize;

use crate::config::packages_dir;
use crate::errors::DegenError;
use crate::tool::ToolConfig;

/// The packages compiled into the binary, named by [`crate::App::bundled`].
/// They work with no install step; an installed package with the same id takes
/// their place.
fn bundled_dir() -> &'static Dir<'static> {
    crate::app().bundled
}

/// `integration.json` — the package manifest, shared with metalcraft integrations.
#[derive(Debug, Clone, Deserialize)]
pub struct Integration {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    /// The only credentials this package's tools may use.
    #[serde(default)]
    pub requires_env: Vec<String>,
}

/// Where a package's files live.
pub enum Source {
    /// `~/.degen-tools/packages/<id>/`
    Installed(PathBuf),
    /// Compiled into the binary from `packages/<id>/`.
    Bundled(&'static Dir<'static>),
}

pub struct Package {
    pub source: Source,
    pub integration: Integration,
}

impl Package {
    pub fn load(dir: &Path) -> Result<Self, DegenError> {
        let path = dir.join("integration.json");
        let integration = parse(&fs::read(&path)?, &path.display().to_string())?;
        Ok(Self { source: Source::Installed(dir.to_path_buf()), integration })
    }

    /// A package compiled into the binary, by id.
    pub fn bundled(id: &str) -> Option<Self> {
        let dir = bundled_dir().get_dir(id)?;
        let file = dir.get_file(format!("{id}/integration.json"))?;
        let integration = parse(file.contents(), &format!("bundled {id}/integration.json")).ok()?;
        Some(Self { source: Source::Bundled(dir), integration })
    }

    pub fn id(&self) -> &str {
        &self.integration.id
    }

    /// First-party: shipped with this binary rather than installed from elsewhere.
    pub fn is_bundled(&self) -> bool {
        matches!(self.source, Source::Bundled(_))
    }

    /// Every tool in `api_tools/`, sorted by name.
    pub fn tools(&self) -> Result<Vec<ToolConfig>, DegenError> {
        let mut tools = Vec::new();
        for (name, bytes) in self.files("api_tools", "json") {
            let tool: ToolConfig = serde_json::from_slice(&bytes)
                .map_err(|e| DegenError::InvalidPackage(format!("{}/{name}: {e}", self.id())))?;
            tools.push(tool);
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(tools)
    }

    /// `(name, markdown)` for every skill file in `skills/`.
    pub fn skills(&self) -> Vec<(String, String)> {
        self.files("skills", "md")
            .into_iter()
            .filter_map(|(name, bytes)| {
                let stem = name.strip_suffix(".md")?.to_string();
                Some((stem, String::from_utf8(bytes).ok()?))
            })
            .collect()
    }

    /// `(file name, contents)` of the files in `subdir` with extension `ext`, sorted.
    fn files(&self, subdir: &str, ext: &str) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = match &self.source {
            Source::Installed(dir) => {
                let Ok(entries) = fs::read_dir(dir.join(subdir)) else {
                    return Vec::new();
                };
                entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == ext))
                    .filter_map(|p| Some((p.file_name()?.to_str()?.to_string(), fs::read(&p).ok()?)))
                    .collect()
            }
            Source::Bundled(dir) => {
                let Some(sub) = dir.get_dir(format!("{}/{subdir}", self.id())) else {
                    return Vec::new();
                };
                sub.files()
                    .filter(|f| f.path().extension().is_some_and(|x| x == ext))
                    .filter_map(|f| Some((f.path().file_name()?.to_str()?.to_string(), f.contents().to_vec())))
                    .collect()
            }
        };
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

fn parse(bytes: &[u8], what: &str) -> Result<Integration, DegenError> {
    serde_json::from_slice(bytes).map_err(|e| DegenError::InvalidPackage(format!("{what}: {e}")))
}

pub fn bundled_ids() -> Vec<String> {
    let mut ids: Vec<String> = bundled_dir()
        .dirs()
        .filter_map(|d| d.path().file_name()?.to_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

/// Package ids are directory names, so they are kept to a safe alphabet.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with(['-', '_'])
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Packages installed under `~/.degen-tools/packages/`.
pub fn installed() -> Result<Vec<Package>, DegenError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(packages_dir()?)? {
        let path = entry?.path();
        let hidden = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.'));
        if hidden || !path.join("integration.json").is_file() {
            continue;
        }
        match Package::load(&path) {
            Ok(pkg) => out.push(pkg),
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }
    out.sort_by(|a, b| a.id().cmp(b.id()));
    Ok(out)
}

/// Every usable package: installed ones, plus bundled ones not overridden by an install.
pub fn available() -> Result<Vec<Package>, DegenError> {
    let mut out = installed()?;
    for id in bundled_ids() {
        if !out.iter().any(|p| p.id() == id)
            && let Some(pkg) = Package::bundled(&id)
        {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| a.id().cmp(b.id()));
    Ok(out)
}

pub fn find(id: &str) -> Result<Package, DegenError> {
    if !valid_id(id) {
        return Err(DegenError::PackageNotFound(id.to_string()));
    }
    let dir = packages_dir()?.join(id);
    if dir.join("integration.json").is_file() {
        return Package::load(&dir);
    }
    Package::bundled(id).ok_or_else(|| DegenError::PackageNotFound(id.to_string()))
}

/// Resolve `tool` or `package/tool` to its package and config. A name found in
/// two packages is an error rather than a silent first match.
pub fn find_tool(reference: &str) -> Result<(Package, ToolConfig), DegenError> {
    if let Some((pkg_id, name)) = reference.split_once('/') {
        let pkg = find(pkg_id)?;
        let tool = pkg
            .tools()?
            .into_iter()
            .find(|t| t.name == name)
            .ok_or_else(|| DegenError::ToolNotFound(reference.to_string()))?;
        return Ok((pkg, tool));
    }

    let mut matches = Vec::new();
    for pkg in available()? {
        let Ok(tools) = pkg.tools() else { continue };
        if let Some(tool) = tools.into_iter().find(|t| t.name == reference) {
            matches.push((pkg, tool));
        }
    }
    match matches.len() {
        0 => Err(DegenError::ToolNotFound(reference.to_string())),
        1 => Ok(matches.remove(0)),
        _ => Err(DegenError::AmbiguousTool {
            tool: reference.to_string(),
            packages: matches.iter().map(|(p, _)| p.id().to_string()).collect(),
        }),
    }
}

