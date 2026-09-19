use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use crate::errors::DegenError;
use crate::project::{self, ProjectEnv};

/// Stored credentials, keyed by the environment-variable name packages ask for
/// (`FAL_KEY`, `CLOUDFLARE_API_TOKEN`, ...).
#[derive(Serialize, Deserialize, Default)]
pub struct Credentials {
    /// The global store, `~/.degen-tools/credentials.json`.
    #[serde(default)]
    pub keys: HashMap<String, String>,
    /// The project `.env` for the current directory, which wins over `keys`.
    #[serde(skip)]
    pub project: Option<ProjectEnv>,
}

/// Where a credential's value came from.
pub enum Source {
    Project(PathBuf),
    Global,
    Environment,
}

/// Returns the binary's state directory (`~/.degen-tools`), creating it if needed.
pub fn data_dir() -> Result<PathBuf, DegenError> {
    let home = dirs::home_dir().ok_or_else(|| {
        DegenError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })?;
    let dir = home.join(crate::app().dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Returns `<state directory>/packages`, creating it if needed.
pub fn packages_dir() -> Result<PathBuf, DegenError> {
    let dir = data_dir()?.join("packages");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn credentials_path() -> Result<PathBuf, DegenError> {
    Ok(data_dir()?.join("credentials.json"))
}

/// The global store plus the project `.env` for the current directory.
pub fn load_credentials() -> Result<Credentials, DegenError> {
    let path = credentials_path()?;
    let mut creds: Credentials = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?)?
    } else {
        Credentials::default()
    };
    creds.project = project::current();
    Ok(creds)
}

pub fn save_credentials(creds: &Credentials) -> Result<(), DegenError> {
    let path = credentials_path()?;
    let data = serde_json::to_string_pretty(creds)?;
    // Written beside the real file with owner-only permissions from the start,
    // then renamed over it: the keys are never readable by others, even briefly.
    let tmp = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    std::io::Write::write_all(&mut file, data.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// The value for credential `name`: the project `.env`, then the global store,
/// then the process environment. Blank values count as unset: an empty
/// `FAL_KEY=` would otherwise send `Authorization: Key ` and earn a 401.
pub fn lookup_credential(creds: &Credentials, name: &str) -> Option<String> {
    resolve_credential(creds, name).map(|(value, _)| value)
}

pub fn resolve_credential(creds: &Credentials, name: &str) -> Option<(String, Source)> {
    let present = |v: &&String| !v.trim().is_empty();
    if let Some(p) = &creds.project
        && let Some(v) = p.vars.get(name).filter(present)
    {
        return Some((v.clone(), Source::Project(p.path.clone())));
    }
    if let Some(v) = creds.keys.get(name).filter(present) {
        return Some((v.clone(), Source::Global));
    }
    std::env::var(name).ok().filter(|v| !v.trim().is_empty()).map(|v| (v, Source::Environment))
}

/// Which call a credential is being resolved for. degen-tools ignores it;
/// degen-portal needs it to pick the account an OAuth token belongs to.
pub struct CallContext<'a> {
    pub package: &'a str,
    pub tool: &'a str,
    /// Which connected account to act as, when the binary has accounts and the
    /// caller named one.
    pub account: Option<&'a str>,
}

/// How a `$NAME` a package declares in `requires_env` becomes a value.
///
/// degen-tools resolves from the credential store and nothing else.
/// degen-portal resolves the same way, and additionally mints a live OAuth
/// access token — refreshing it first when it is about to expire, which is why
/// this returns a `Result` rather than an `Option`: a failed refresh is an
/// error to report, not a credential that happens to be missing.
pub trait CredentialResolver {
    fn resolve(&self, name: &str, ctx: &CallContext<'_>) -> Result<Option<String>, DegenError>;

    /// `None` when the credential is ready to use; otherwise the command a
    /// human runs to make it ready. Asked by `list` and `skill`, so an agent is
    /// never told to store by hand something that is minted (an OAuth token is
    /// not typed in, it is connected).
    fn missing(&self, name: &str) -> Option<String> {
        stored_or_fix(name)
    }
}

/// The default answer: is it in the store, and if not, how is it put there?
pub fn stored_or_fix(name: &str) -> Option<String> {
    let set = load_credentials().ok().and_then(|c| lookup_credential(&c, name)).is_some();
    if set { None } else { Some(format!("{} auth set {name}", crate::app().name)) }
}

/// The store: this directory's `.env`, then the global file, then the environment.
pub struct StoredCredentials;

impl CredentialResolver for StoredCredentials {
    fn resolve(&self, name: &str, _ctx: &CallContext<'_>) -> Result<Option<String>, DegenError> {
        Ok(lookup_credential(&load_credentials()?, name))
    }
}

/// ~/.degen-tools/registries.json — the package registries `install` and
/// `search` talk to. Any host serving the agent-pack registry protocol works.
#[derive(Serialize, Deserialize)]
pub struct Registries {
    pub default: String,
    pub registries: BTreeMap<String, RegistryEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct RegistryEntry {
    pub url: String,
}

impl Default for Registries {
    fn default() -> Self {
        let mut registries = BTreeMap::new();
        registries.insert(
            "axoniac".to_string(),
            RegistryEntry { url: "https://axoniac.com".to_string() },
        );
        Self { default: "axoniac".to_string(), registries }
    }
}

pub fn load_registries() -> Result<Registries, DegenError> {
    let path = data_dir()?.join("registries.json");
    if !path.exists() {
        return Ok(Registries::default());
    }
    let data = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data)?)
}
