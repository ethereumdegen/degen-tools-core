//! The engine two binaries share: degen-tools (devops APIs, static keys) and
//! degen-portal (social APIs, OAuth tokens).
//!
//! Everything here is provider-agnostic. A tool is a JSON file in the metalcraft
//! integration format; running one means filling `$NAME` placeholders from a
//! [`config::CredentialResolver`], sending one HTTP request, and masking every
//! secret on the way back out. The parts that differ between binaries — where
//! state lives, which packages are compiled in, and how a credential becomes a
//! value — are named once in [`App`] and set by [`init`].
//!
//! The masking, the `requires_env` allowlist and the loopback API's lockdown are
//! security surface for both binaries, which is why they live in one crate and
//! not in two copies.

pub mod args;
pub mod auth;
pub mod config;
pub mod errors;
pub mod install;
pub mod package;
pub mod paths;
pub mod project;
pub mod run;
pub mod server;
pub mod skill;
pub mod tool;

use std::sync::OnceLock;

use include_dir::Dir;

/// What differs between the binaries built on this crate.
pub struct App {
    /// The binary's name, as it appears in messages: `degen-tools`.
    pub name: &'static str,
    /// Its version, reported by `/health` and `/v1/status`.
    pub version: &'static str,
    /// Its state directory under `$HOME`: `.degen-tools`.
    pub dir: &'static str,
    /// Prefix of the variables `connect` prints: `DEGEN_TOOLS`.
    pub env_prefix: &'static str,
    /// Sent as `User-Agent` on every tool call.
    pub user_agent: &'static str,
    /// Packages compiled into the binary, one directory per package id.
    pub bundled: &'static Dir<'static>,
    /// How a `$NAME` a package declares becomes a value.
    pub credentials: &'static (dyn config::CredentialResolver + Send + Sync),
    /// Checked before a request is sent.
    pub policy: &'static (dyn CallPolicy + Send + Sync),
    /// A tool name for the example `connect` prints.
    pub example_tool: &'static str,
    /// The agent-facing overview `skill` prints with no arguments. `{packages}`
    /// and `{version}` are filled in.
    pub overview: &'static str,
}

/// What a call is allowed to do, decided before it is sent and recorded after.
///
/// degen-tools sends whatever a tool describes: its calls are private,
/// reversible and addressed to one account's own infrastructure. degen-portal's
/// are public, permanent and billed, so it answers here.
pub trait CallPolicy {
    /// Run before the request is built. Refusing costs nothing; holding
    /// returns a result of the policy's own making instead of calling out.
    fn check(
        &self,
        tool: &tool::ToolConfig,
        args: &serde_json::Map<String, serde_json::Value>,
        ctx: &config::CallContext<'_>,
    ) -> Result<Verdict, errors::DegenError>;

    /// Run after a call came back, successful or not. This is where a policy
    /// counts what was spent and writes down what was published.
    fn record(
        &self,
        _tool: &tool::ToolConfig,
        _args: &serde_json::Map<String, serde_json::Value>,
        _ctx: &config::CallContext<'_>,
        _outcome: &run::Outcome,
    ) {
    }
}

/// Send it, or don't and say this happened instead.
pub enum Verdict {
    Send,
    /// The call was not made. The outcome describes what was done with it —
    /// queued for a human, say — and is returned to the caller as-is.
    Hold(Box<run::Outcome>),
}

/// No call is refused, nothing is recorded.
pub struct AllowEveryCall;

impl CallPolicy for AllowEveryCall {
    fn check(
        &self,
        _tool: &tool::ToolConfig,
        _args: &serde_json::Map<String, serde_json::Value>,
        _ctx: &config::CallContext<'_>,
    ) -> Result<Verdict, errors::DegenError> {
        Ok(Verdict::Send)
    }
}

static APP: OnceLock<App> = OnceLock::new();

/// Name the binary before doing anything else. The first call wins.
pub fn init(app: App) {
    let _ = APP.set(app);
}

/// Unit tests exercise the engine with no binary around them.
#[cfg(test)]
static TEST_BUNDLED: Dir<'static> = Dir::new("", &[]);

pub fn app() -> &'static App {
    #[cfg(test)]
    {
        return APP.get_or_init(|| App {
            name: "degen-core",
            version: env!("CARGO_PKG_VERSION"),
            example_tool: "example_tool",
            overview: "# degen-core\n\n{packages}",
            dir: ".degen-core-test",
            env_prefix: "DEGEN_CORE",
            user_agent: "degen-core/test",
            bundled: &TEST_BUNDLED,
            policy: &AllowEveryCall,
            credentials: &config::StoredCredentials,
        });
    }
    #[cfg(not(test))]
    APP.get().expect("degen_core::init() must be called before anything else")
}
