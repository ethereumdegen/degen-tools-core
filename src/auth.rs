use std::io::{IsTerminal, Read};

use crate::config::{Source, load_credentials, resolve_credential, save_credentials};
use crate::errors::DegenError;

fn mask(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() > 12 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}...{tail} ({} chars)", chars.len())
    } else {
        format!("**** ({} chars)", chars.len())
    }
}

/// Credential names look like environment variables: `NEON_API_KEY`, `DD_DATABASE_URL`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The value given on the command line, or read from stdin when it was left out,
/// so a key can be piped in (`pbpaste | degen-tools auth set NEON_API_KEY`)
/// without landing in shell history or an agent's transcript.
pub fn value_or_stdin(name: &str, value: Option<&str>) -> Result<String, DegenError> {
    if let Some(v) = value {
        return Ok(v.to_string());
    }
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("Paste the value for {name}, then press Enter and Ctrl-D:");
    }
    let mut buf = String::new();
    stdin.read_to_string(&mut buf)?;
    let v = buf.trim().to_string();
    if v.is_empty() {
        return Err(DegenError::InvalidArgs(format!("no value given for {name}")));
    }
    Ok(v)
}

/// Where a write lands: the project `.env` when there is a project to write
/// to (inside a git repository, or a directory that already has a `.env`),
/// unless `global` says otherwise.
pub fn store(name: &str, value: &str, global: bool) -> Result<String, DegenError> {
    if !valid_name(name) {
        return Err(DegenError::InvalidArgs(format!(
            "'{name}' is not a credential name; use letters, digits and underscores, like NEON_API_KEY"
        )));
    }
    let mut creds = load_credentials()?;
    match creds.project.as_mut().filter(|p| !global && (p.in_git || p.path.is_file())) {
        Some(project) => {
            project.write(name, value)?;
            Ok(project.path.display().to_string())
        }
        None => {
            creds.keys.insert(name.to_string(), value.to_string());
            save_credentials(&creds)?;
            Ok("the global store".to_string())
        }
    }
}

pub fn set(name: &str, value: Option<&str>, global: bool) -> Result<(), DegenError> {
    let value = value_or_stdin(name, value)?;
    let place = store(name, &value, global)?;
    println!("✓ {name} stored in {place}");
    Ok(())
}

fn describe(source: &Source) -> String {
    match source {
        Source::Project(path) => path.display().to_string(),
        Source::Global => "global store".to_string(),
        Source::Environment => "shell environment".to_string(),
    }
}

pub fn get(name: &str, unmask: bool) -> Result<(), DegenError> {
    let creds = load_credentials()?;
    let (value, source) = resolve_credential(&creds, name).ok_or_else(|| DegenError::CredentialNotFound(name.to_string()))?;
    if unmask {
        println!("{value}");
    } else {
        println!("{}  ({})", mask(&value), describe(&source));
        eprintln!("(credential is masked — use --unmask to reveal)");
    }
    Ok(())
}

/// Every credential the current directory can see, marking which value wins.
pub fn list() -> Result<(), DegenError> {
    let creds = load_credentials()?;
    let mut rows: Vec<(String, String, String)> = Vec::new();
    if let Some(p) = &creds.project {
        for (k, v) in &p.vars {
            rows.push((k.clone(), mask(v), p.path.display().to_string()));
        }
    }
    for (k, v) in &creds.keys {
        let shadowed = creds.project.as_ref().is_some_and(|p| p.vars.get(k).is_some_and(|pv| !pv.trim().is_empty()));
        let place = if shadowed { "global store (overridden by the project .env)" } else { "global store" };
        rows.push((k.clone(), mask(v), place.to_string()));
    }
    match &creds.project {
        Some(p) if p.path.is_file() => println!("Project .env: {}", p.path.display()),
        _ => println!("Project .env: none here"),
    }
    if rows.is_empty() {
        println!("No credentials. Store one with: {} auth set <NAME>", crate::app().name);
        return Ok(());
    }
    rows.sort();
    println!();
    println!("{:<32} {:<26} FROM", "NAME", "VALUE");
    println!("{}", "-".repeat(90));
    for (name, value, place) in rows {
        println!("{name:<32} {value:<26} {place}");
    }
    Ok(())
}

pub fn remove(name: &str, global: bool) -> Result<(), DegenError> {
    let mut creds = load_credentials()?;
    if !global
        && let Some(project) = creds.project.as_mut()
        && project.remove(name)?
    {
        println!("✓ Removed {name} from {}", project.path.display());
        return Ok(());
    }
    if creds.keys.remove(name).is_none() {
        return Err(DegenError::CredentialNotFound(name.to_string()));
    }
    save_credentials(&creds)?;
    println!("✓ Removed {name} from the global store");
    Ok(())
}
