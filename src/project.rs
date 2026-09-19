//! Project-scoped credentials: the `.env` in the directory you run degen-tools
//! from. Different repos use different databases and accounts, so a key found
//! there wins over the global store for that command.
//!
//! The `.env` is the one in the current directory, or the nearest one above it
//! up to the repository root, so running from `starcast/sc-backend` still finds
//! `starcast/.env`. The search never leaves the repository (or, outside one, the
//! current directory), so an unrelated `.env` higher up is never picked up.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::errors::DegenError;

pub const ENV_FILE: &str = ".env";

pub struct ProjectEnv {
    /// The directory holding the `.env` (or where a new one would go).
    pub root: PathBuf,
    /// `<root>/.env`, whether or not it exists yet.
    pub path: PathBuf,
    /// Inside a git repository, so writes must be git-ignored.
    pub in_git: bool,
    pub vars: HashMap<String, String>,
}

/// The project `.env` for the current directory.
pub fn current() -> Option<ProjectEnv> {
    let cwd = std::env::current_dir().ok()?;
    let (root, in_git) = find_root(&cwd);
    Some(load(root, in_git))
}

/// The nearest directory from `start` up to the repository root that holds a
/// `.env`; with none, the repository root. Outside a repository only `start`
/// itself is considered, so a stray `~/.env` never leaks into a command.
fn find_root(start: &Path) -> (PathBuf, bool) {
    let Some(repo) = start.ancestors().find(|d| d.join(".git").exists()) else {
        return (start.to_path_buf(), false);
    };
    let nearest = start
        .ancestors()
        .take_while(|d| d.starts_with(repo))
        .find(|d| d.join(ENV_FILE).is_file())
        .unwrap_or(repo);
    (nearest.to_path_buf(), true)
}

fn load(root: PathBuf, in_git: bool) -> ProjectEnv {
    let path = root.join(ENV_FILE);
    let mut vars = HashMap::new();
    if path.is_file() {
        match dotenvy::from_path_iter(&path) {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((k, v)) => {
                            vars.insert(k, v);
                        }
                        Err(e) => {
                            eprintln!("warning: {}: {e} (the rest of the file is skipped)", path.display());
                            break;
                        }
                    }
                }
            }
            Err(e) => eprintln!("warning: could not read {}: {e}", path.display()),
        }
    }
    ProjectEnv { root, path, in_git, vars }
}

impl ProjectEnv {
    /// Refuse to put secrets in a `.env` git would commit.
    pub fn ensure_ignored(&self) -> Result<(), DegenError> {
        if !self.in_git {
            return Ok(());
        }
        let ignored = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["check-ignore", "-q", ENV_FILE])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ignored {
            return Ok(());
        }
        Err(DegenError::InvalidArgs(format!(
            "{} is not ignored by git, so {} will not write secrets into it.\n\n  \
             Add `.env` to the repository's .gitignore, or store this one globally with --global",
            self.path.display(),
            crate::app().name
        )))
    }

    /// Set `name` in the `.env`, replacing an existing line or appending one.
    /// Everything else in the file (comments, order, other keys) is kept.
    pub fn write(&mut self, name: &str, value: &str) -> Result<(), DegenError> {
        self.ensure_ignored()?;
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        let line = format!("{name}={}", quote(value));
        let mut replaced = false;
        let mut lines: Vec<String> = text
            .lines()
            .map(|l| {
                if !replaced && defines(l, name) {
                    replaced = true;
                    line.clone()
                } else {
                    l.to_string()
                }
            })
            .collect();
        if !replaced {
            lines.push(line);
        }
        write_file(&self.path, &(lines.join("\n") + "\n"))?;
        self.vars.insert(name.to_string(), value.to_string());
        Ok(())
    }

    /// Remove `name` from the `.env`. Returns whether it was there.
    pub fn remove(&mut self, name: &str) -> Result<bool, DegenError> {
        let Ok(text) = fs::read_to_string(&self.path) else { return Ok(false) };
        let kept: Vec<&str> = text.lines().filter(|l| !defines(l, name)).collect();
        if kept.len() == text.lines().count() {
            return Ok(false);
        }
        write_file(&self.path, &(kept.join("\n") + "\n"))?;
        self.vars.remove(name);
        Ok(true)
    }
}

/// `NAME=...` or `export NAME=...`, ignoring surrounding whitespace.
fn defines(line: &str, name: &str) -> bool {
    let l = line.trim_start();
    let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
    l.strip_prefix(name).is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// Single quotes keep a value literal (no `$VAR` expansion); a value holding a
/// single quote gets double quotes with its specials escaped.
fn quote(value: &str) -> String {
    if !value.contains('\'') {
        return format!("'{value}'");
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$");
    format!("\"{escaped}\"")
}

/// A new `.env` is created owner-only; an existing one keeps its permissions.
fn write_file(path: &Path, text: &str) -> Result<(), DegenError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("degen-tools-core-project-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        let ok = Command::new("git").arg("init").arg("-q").arg(&dir).status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "git init failed");
        dir
    }

    #[test]
    fn values_round_trip_through_the_file_untouched() {
        let dir = temp_repo("roundtrip");
        fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        fs::write(dir.join(".env"), "# local dev\nexport PORT=3000\nFAL_KEY=old\n").unwrap();
        assert_eq!(find_root(&dir.join("sub/deeper")), (dir.clone(), true));

        let mut env = load(dir.clone(), true);
        let tricky = [
            ("FAL_KEY", "new-key"),
            ("DD_DATABASE_URL", "postgresql://u:p$ss@ep-x-pooler.us-east-1.aws.neon.tech/dd?sslmode=require"),
            ("WEIRD", r#"it's "quoted" $HOME \ back"#),
        ];
        for (k, v) in tricky {
            env.write(k, v).unwrap();
        }
        let reloaded = load(dir.clone(), true);
        for (k, v) in tricky {
            assert_eq!(reloaded.vars.get(k).map(String::as_str), Some(v), "{k}");
        }
        let text = fs::read_to_string(dir.join(".env")).unwrap();
        assert!(text.starts_with("# local dev\nexport PORT=3000\nFAL_KEY='new-key'\n"), "{text}");

        let mut env = reloaded;
        assert!(env.remove("WEIRD").unwrap());
        assert!(!load(dir.clone(), true).vars.contains_key("WEIRD"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_nearest_env_wins_but_the_search_stays_in_the_repo() {
        let dir = temp_repo("nearest");
        fs::write(dir.join("sub/.env"), "A=sub\n").unwrap();
        assert_eq!(find_root(&dir.join("sub/deeper")), (dir.join("sub"), true));
        assert_eq!(find_root(&dir), (dir.clone(), true));
        let outside = std::env::temp_dir().join(format!("degen-tools-core-noproject-{}", std::process::id()));
        fs::create_dir_all(&outside).unwrap();
        assert_eq!(find_root(&outside), (outside.clone(), false));
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_env_git_would_commit_is_refused() {
        let dir = temp_repo("tracked");
        let mut env = load(dir.clone(), true);
        assert!(env.write("FAL_KEY", "x").is_err());
        assert!(!dir.join(".env").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
