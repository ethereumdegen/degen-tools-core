use std::fmt;

#[derive(Debug)]
pub enum DegenError {
    PackageNotFound(String),
    ToolNotFound(String),
    AmbiguousTool { tool: String, packages: Vec<String> },
    CredentialNotFound(String),
    InvalidArgs(String),
    InvalidPackage(String),
    Http(String),
    IoError(std::io::Error),
    JsonError(serde_json::Error),
}

impl fmt::Display for DegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageNotFound(p) => {
                writeln!(f, "no package named '{p}'")?;
                writeln!(f)?;
                writeln!(f, "  Packages:    {} list", crate::app().name)?;
                write!(f, "  Find more:   {} search <words>", crate::app().name)
            }
            Self::ToolNotFound(t) => {
                writeln!(f, "no package has a tool named '{t}'")?;
                writeln!(f)?;
                writeln!(f, "  Packages:          {} list", crate::app().name)?;
                write!(f, "  A package's tools:   {} skill <package>", crate::app().name)
            }
            Self::AmbiguousTool { tool, packages } => {
                writeln!(f, "tool '{tool}' exists in more than one package: {}", packages.join(", "))?;
                writeln!(f)?;
                write!(f, "  Name the package:  {} run {}/{tool} ...", crate::app().name, packages[0])
            }
            Self::CredentialNotFound(name) => {
                writeln!(f, "{name} is not set")?;
                writeln!(f)?;
                writeln!(f, "  To fix:  {} auth set {name}   (reads the value from stdin)", crate::app().name)?;
                write!(f, "  Or, for one call:  {} run --cred <VAR>={name} ...", crate::app().name)
            }
            Self::InvalidArgs(m) => write!(f, "{m}"),
            Self::InvalidPackage(m) => write!(f, "invalid package: {m}"),
            Self::Http(m) => write!(f, "{m}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::JsonError(e) => write!(f, "config error: {e}"),
        }
    }
}

impl From<std::io::Error> for DegenError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_json::Error> for DegenError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}
