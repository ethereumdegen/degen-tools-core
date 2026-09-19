# degen-core

The engine two binaries share:
[degen-tools](https://github.com/ethereumdegen/degen-tools) (devops APIs, static
keys) and [degen-portal](https://github.com/ethereumdegen/degen-portal) (Discord
and X, OAuth accounts, a posting policy).

Nothing here knows about a specific service. A tool is a JSON file in the
[metalcraft integration format](https://github.com/rust4ai/metalcraft-agent/blob/master/specs/AGENT_PACK_FORMAT.md):
running one means filling `$NAME` placeholders from a credential resolver,
sending exactly one HTTP request, and masking every secret on the way back out.

It lives on its own because the masking, the `requires_env` allowlist and the
loopback API's lockdown are the security surface of both binaries. One copy
means a fix lands once.

## What it provides

| Module | |
|---|---|
| `package` | `integration.json` + `api_tools/*.json`, bundled into a binary or installed from a registry |
| `tool` | One HTTP tool: URL templating, `$NAME` expansion limited to declared credentials, host allowlist, body mappings (`none`, `params`, `params_nested`, `template`, `multipart`) |
| `run` | Build the request, send it, mask the response, save media and secrets |
| `config` | Per-project `.env` then a global store then the environment; the `CredentialResolver` seam |
| `paths` | Response paths: `data.id`, `images[].url`, `connection_uris[0].uri` |
| `args` | Type `--name value` arguments against a tool's JSON schema |
| `auth`, `project`, `install`, `skill` | Credential storage, project scoping, package install, agent-facing docs |
| `server` | The loopback JSON API: 127.0.0.1 only, per-run bearer token, browser requests refused |

## Using it

A binary names itself once, before anything reads state:

```rust
use degen_core::{App, AllowEveryCall, config::StoredCredentials};
use include_dir::{Dir, include_dir};

static BUNDLED: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/packages");

degen_core::init(App {
    name: "degen-tools",
    version: env!("CARGO_PKG_VERSION"),
    dir: ".degen-tools",              // ~/.degen-tools
    env_prefix: "DEGEN_TOOLS",        // DEGEN_TOOLS_URL, DEGEN_TOOLS_TOKEN
    user_agent: concat!("degen-tools/", env!("CARGO_PKG_VERSION")),
    bundled: &BUNDLED,
    credentials: &StoredCredentials,  // or something that mints OAuth tokens
    policy: &AllowEveryCall,          // or something that refuses and records
    example_tool: "neon_list_projects",
    overview: include_str!("skill.md"),
});
```

Two traits are the whole extension surface:

- **`CredentialResolver`** turns a `$NAME` into a value. degen-tools reads the
  store; degen-portal also mints and refreshes OAuth access tokens, which is why
  it returns a `Result` — a failed refresh must be reported as itself, not as a
  credential that looks unset.
- **`CallPolicy`** decides before a request is built (`Send`, refuse, or `Hold`
  it for a human) and is told the outcome afterwards. degen-tools allows
  everything; degen-portal enforces a channel allowlist, a repeat window and
  per-provider budgets, then writes the result to a ledger.

## License

MIT
