use serde_json::Value;

use crate::errors::DegenError;
use crate::package::{self, Package};
use crate::tool::ToolConfig;

/// `skill [name]` — `name` may be a package id or a tool name.
pub fn show(name: Option<&str>) -> Result<(), DegenError> {
    let text = match name {
        None => main_skill()?,
        Some(name) => match package::find(name) {
            Ok(pkg) => package_skill(&pkg)?,
            Err(_) => {
                let (_, tool) = package::find_tool(name)?;
                tool_section(&tool)
            }
        },
    };
    println!("{text}");
    Ok(())
}

/// The binary's own overview ([`crate::App::overview`]) with `{packages}`
/// filled in from what is actually installed.
fn main_skill() -> Result<String, DegenError> {
    let app = crate::app();
    let mut listing = String::new();
    for pkg in package::available()? {
        let count = pkg.tools().map(|t| t.len()).unwrap_or(0);
        let summary = if pkg.integration.name.is_empty() { pkg.id() } else { pkg.integration.name.as_str() };
        let source = if pkg.is_bundled() { "" } else { ", installed" };
        listing.push_str(&format!(
            "- `{}`: {summary} ({count} tools{source}) → `{} skill {}`\n",
            pkg.id(),
            app.name,
            pkg.id()
        ));
    }
    Ok(app.overview.replace("{packages}", &listing).replace("{version}", app.version))
}

/// A package's guide and tool reference, for the local API.
pub fn package_guide(pkg: &Package) -> String {
    package_skill(pkg).unwrap_or_default()
}

fn package_skill(pkg: &Package) -> Result<String, DegenError> {
    let i = &pkg.integration;
    let tools = pkg.tools()?;
    let mut out = format!(
        "---\nskill: {}\nversion: {}\nrequires_env: [{}]\n---\n\n# {} (`{}`)\n\n{}\n",
        i.id,
        i.version,
        i.requires_env.join(", "),
        if i.name.is_empty() { &i.id } else { &i.name },
        i.id,
        i.description
    );

    out.push_str("\n## Credentials\n\n");
    if i.requires_env.is_empty() {
        out.push_str("None — this package needs no key.\n");
    }
    for var in &i.requires_env {
        match crate::app().credentials.missing(var) {
            None => out.push_str(&format!("- `{var}`: set\n")),
            Some(fix) => out.push_str(&format!("- `{var}`: NOT SET. Ask the user to run `{fix}` in their terminal\n")),
        }
    }

    for (_, body) in pkg.skills() {
        out.push_str("\n---\n\n");
        out.push_str(strip_frontmatter(&body).trim());
        out.push('\n');
    }

    out.push_str(&format!("\n---\n\n## Tools ({})\n", tools.len()));
    for tool in &tools {
        out.push('\n');
        out.push_str(&tool_section(tool));
    }
    Ok(out)
}

/// A skill file opens with a YAML block for humans and listings; a caller that
/// wants the prose alone (an MCP `instructions` string) does not want it.
pub fn strip_frontmatter(md: &str) -> &str {
    let Some(rest) = md.strip_prefix("---\n") else {
        return md;
    };
    match rest.find("\n---") {
        Some(end) => rest[end + 4..].trim_start_matches(['-', '\n']),
        None => md,
    }
}

fn tool_section(tool: &ToolConfig) -> String {
    let props = tool
        .parameters
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required: Vec<&str> = tool
        .parameters
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let type_of = |p: &Value| match p.get("enum").and_then(Value::as_array) {
        Some(options) => options
            .iter()
            .map(|o| o.as_str().map(str::to_string).unwrap_or_else(|| o.to_string()))
            .collect::<Vec<_>>()
            .join("|"),
        None => p.get("type").and_then(Value::as_str).unwrap_or("value").to_string(),
    };

    // Required first, each group in the order the schema's author wrote.
    let is_required = |name: &String| required.contains(&name.as_str());
    let ordered: Vec<(&String, &Value)> = props
        .iter()
        .filter(|(n, _)| is_required(n))
        .chain(props.iter().filter(|(n, _)| !is_required(n)))
        .collect();

    let mut usage = format!("{} run {}", crate::app().name, tool.name);
    for (name, p) in &ordered {
        let arg = format!("--{name} <{}>", type_of(p));
        if is_required(name) {
            usage.push_str(&format!(" {arg}"));
        } else {
            usage.push_str(&format!(" [{arg}]"));
        }
    }
    if tool.parameters.get("additionalProperties") == Some(&Value::Bool(true)) {
        usage.push_str(" [--<any> <value>]");
    }

    let mut out = format!("### {}\n\n{}\n\n```bash\n{usage}\n```\n", tool.name, tool.description);
    if !props.is_empty() {
        out.push_str("\n| Parameter | Type | Required | Description |\n|---|---|---|---|\n");
        for (name, p) in &ordered {
            let desc = p.get("description").and_then(Value::as_str).unwrap_or("").replace('|', "\\|").replace('\n', " ");
            let req = if required.contains(&name.as_str()) { "yes" } else { "" };
            out.push_str(&format!("| `{name}` | {} | {req} | {desc} |\n", type_of(p)));
        }
    }
    if !tool.save.is_empty() {
        out.push_str("\nMedia URLs in the response are downloaded; `--out <file-or-dir>` picks where.\n");
    }
    if !tool.save_inline.is_empty() {
        out.push_str(&format!(
            "\nFiles returned inline ({}) are written to disk and replaced in the output by their path; `--out <file-or-dir>` picks where.\n",
            tool.save_inline.iter().map(|s| format!("`{}` as .{}", s.path, s.ext)).collect::<Vec<_>>().join(", ")
        ));
    }
    if !tool.secret_paths.is_empty() {
        out.push_str(&format!(
            "\nSecrets in the response ({}) print masked; store one with `--save-secret NAME` (or `NAME=<path>`).\n",
            tool.secret_paths.iter().map(|p| format!("`{p}`")).collect::<Vec<_>>().join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontmatter_is_stripped() {
        assert_eq!(strip_frontmatter("---\ndescription: x\n---\n\n# Body\n"), "# Body\n");
        assert_eq!(strip_frontmatter("# No frontmatter"), "# No frontmatter");
    }
}
