//! Keeps the four places a GRASP-P setting is written down in step.
//!
//! A setting lives in `src/config.rs` (clap), `docs/reference/configuration.md`,
//! `.env.example` and `nix/module.nix`. Only review held the last three to
//! the first, and a setting that reaches fewer than four leaves an operator
//! with a switch the reference does not mention, or a NixOS module that
//! cannot set it. These tests take the settings from clap and look for each
//! one in the other three files, so a change that adds, renames or removes a
//! setting fails until all four agree.
//!
//! Each file is matched by its own structure, never by line number and never
//! by the wording of a description:
//!
//! - the reference: a heading that holds the name in backticks, and under it
//!   the `**Default:**` line, whose value is in backticks;
//! - `.env.example`: the `NAME=value` line, commented out or not, and the
//!   `# Default:` line of the comment block above it;
//! - the NixOS module: the `NAME = ...;` entry of the environment map, the
//!   `cfg.<option>` that entry reads, and that option's `default = ...;`.
//!
//! A default is compared only where it can be read for certain. An unset
//! optional setting, a Nix list, `null` or an expression is left alone. A
//! setting whose default in the code is not empty and whose NixOS default is
//! of that kind has to be named in `NIX_DEFAULT_NOT_COMPARED`, so that its
//! comparison cannot stop without anyone noticing.

use std::collections::BTreeSet;

use clap::CommandFactory;

use crate::config::Config;

const PREFIX: &str = "NGIT_GRASP_P_";

const REFERENCE: &str = "docs/reference/configuration.md";
const ENV_EXAMPLE: &str = ".env.example";
const NIX_MODULE: &str = "nix/module.nix";

/// A GRASP-P setting as clap knows it.
#[derive(Debug, Clone)]
struct Setting {
    name: String,
    /// What clap falls back to; `None` for a setting that may stay unset.
    default: Option<String>,
}

/// The text of the three files that have to agree with clap.
#[derive(Clone, Copy)]
struct Sources<'a> {
    reference: &'a str,
    env_example: &'a str,
    nix_module: &'a str,
}

impl Sources<'static> {
    fn real() -> Self {
        Self {
            reference: include_str!("../../docs/reference/configuration.md"),
            env_example: include_str!("../../.env.example"),
            nix_module: include_str!("../../nix/module.nix"),
        }
    }
}

fn settings() -> Vec<Setting> {
    let mut command = Config::command();
    command.build();
    let settings: Vec<Setting> = command
        .get_arguments()
        .filter_map(|argument| {
            let name = argument.get_env()?.to_str()?;
            name.starts_with(PREFIX).then(|| Setting {
                name: name.to_string(),
                default: argument
                    .get_default_values()
                    .first()
                    .map(|value| value.to_string_lossy().into_owned()),
            })
        })
        .collect();
    assert!(
        !settings.is_empty(),
        "clap reports no {PREFIX}* setting, so these tests would check nothing"
    );
    settings
}

// ---------------------------------------------------------------------------
// docs/reference/configuration.md
// ---------------------------------------------------------------------------

/// The lines under the heading that holds `name` in backticks, up to the
/// next heading. `None` when no heading does.
fn reference_section<'a>(text: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let wanted = format!("`{name}`");
    let mut fenced = false;
    let mut found = false;
    let mut section = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            fenced = !fenced;
        }
        // Inside a code fence a `#` starts a shell comment, not a heading.
        let heading = !fenced && trimmed.starts_with('#');
        if found {
            if heading {
                break;
            }
            section.push(line);
        } else if heading && trimmed.trim_start_matches('#').trim() == wanted {
            found = true;
        }
    }
    found.then_some(section)
}

/// The value in backticks straight after `**Default:**`. `None` when the
/// section has no such line or the line gives no value there, as in
/// `**Default:** unset`.
fn reference_default(section: &[&str]) -> Option<String> {
    let stated = section
        .iter()
        .find_map(|line| line.trim().strip_prefix("**Default:**"))?;
    let value = stated.trim().strip_prefix('`')?;
    let value = &value[..value.find('`')?];
    // The reference writes an empty string as `""`.
    let unquoted = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'));
    Some(unquoted.unwrap_or(value).to_string())
}

// ---------------------------------------------------------------------------
// .env.example
// ---------------------------------------------------------------------------

/// `line` without its comment marker: `# NAME=1` and `NAME=1` both give
/// `NAME=1`.
fn uncommented(line: &str) -> &str {
    line.trim().trim_start_matches('#').trim()
}

/// Where `name` is assigned, with the value of each assignment.
fn env_assignments(lines: &[&str], name: &str) -> Vec<(usize, String)> {
    let mut assignments = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let assigned = uncommented(line)
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='));
        // Prose may wrap so that a line begins `NAME=value and so on`. An
        // assignment is a single word.
        if let Some(value) = assigned.filter(|value| !value.contains(char::is_whitespace)) {
            assignments.push((index, value.to_string()));
        }
    }
    assignments
}

/// The first word after `Default:` in the comment block that ends just above
/// `lines[below]`. `None` when the block has no such line.
fn env_default_line(lines: &[&str], below: usize) -> Option<String> {
    for line in lines[..below].iter().rev() {
        if !line.trim().starts_with('#') {
            break;
        }
        if let Some(stated) = uncommented(line).strip_prefix("Default:") {
            return stated.split_whitespace().next().map(str::to_string);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// nix/module.nix
// ---------------------------------------------------------------------------

/// What follows the `=` when `line` assigns `name`. The name has to end
/// where the `=` begins: `FOO` is not assigned by `FOO_BAR = 1;`.
fn nix_assigned<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let value = line
        .trim_start()
        .strip_prefix(name)?
        .trim_start()
        .strip_prefix('=')?;
    (!value.starts_with('=')).then_some(value)
}

/// The `NAME = ...;` entry of the environment map, up to its semicolon. The
/// value is often on the line after the name.
fn nix_environment_entry(lines: &[&str], name: &str) -> Option<String> {
    let start = lines
        .iter()
        .position(|line| nix_assigned(line, name).is_some())?;
    let mut entry = String::new();
    for line in &lines[start..] {
        entry.push_str(line);
        entry.push(' ');
        if line.contains(';') {
            break;
        }
    }
    Some(entry)
}

/// The option an environment entry reads: the word after `cfg.`. `None` for
/// an entry that reads no option, or one nested in an option set, which this
/// test does not follow.
fn nix_option_read(entry: &str) -> Option<&str> {
    let after = &entry[entry.find("cfg.")? + "cfg.".len()..];
    let end = after
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(after.len());
    if end == 0 || after[end..].starts_with('.') {
        return None;
    }
    Some(&after[..end])
}

/// The line that declares `option` with `mkOption`.
fn nix_option_declaration(lines: &[&str], option: &str) -> Option<usize> {
    lines.iter().position(|line| {
        nix_assigned(line, option).is_some_and(|value| value.trim_start().starts_with("mkOption"))
    })
}

/// The default of `option`, when it is declared with one this test can read.
fn nix_option_default(lines: &[&str], option: &str) -> Option<String> {
    let declared = nix_option_declaration(lines, option)?;
    lines[declared + 1..]
        .iter()
        // The next `mkOption` belongs to the next option.
        .take_while(|line| !line.contains("mkOption"))
        .find_map(|line| nix_assigned(line, "default"))
        .and_then(|value| nix_literal(value.trim().strip_suffix(';')?))
}

/// A Nix value that reaches the server as the same text: a boolean, a whole
/// number or a plain string. Anything else (`null`, a list, arithmetic, an
/// interpolated string) is not compared.
fn nix_literal(value: &str) -> Option<String> {
    let value = value.trim();
    let number = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    if value == "true" || value == "false" || number {
        return Some(value.to_string());
    }
    let text = value.strip_prefix('"')?.strip_suffix('"')?;
    (!text.contains(['"', '$', '\\'])).then(|| text.to_string())
}

// ---------------------------------------------------------------------------
// The three checks
// ---------------------------------------------------------------------------

/// One line for each place a setting is absent from.
fn missing(settings: &[Setting], sources: Sources<'_>) -> Vec<String> {
    let env_lines: Vec<&str> = sources.env_example.lines().collect();
    let nix_lines: Vec<&str> = sources.nix_module.lines().collect();
    let mut problems = Vec::new();
    for setting in settings {
        let name = setting.name.as_str();
        if reference_section(sources.reference, name).is_none() {
            problems.push(format!(
                "{REFERENCE}: {name} has no section (a heading that holds `{name}`)"
            ));
        }
        if env_assignments(&env_lines, name).is_empty() {
            problems.push(format!("{ENV_EXAMPLE}: {name} has no `{name}=value` line"));
        }
        let Some(entry) = nix_environment_entry(&nix_lines, name) else {
            problems.push(format!(
                "{NIX_MODULE}: {name} has no `{name} = ...;` entry in the environment map"
            ));
            continue;
        };
        let undeclared = nix_option_read(&entry)
            .filter(|option| nix_option_declaration(&nix_lines, option).is_none());
        if let Some(option) = undeclared {
            problems.push(format!(
                "{NIX_MODULE}: {name} reads cfg.{option}, and no `{option} = mkOption` declares it"
            ));
        }
    }
    problems
}

/// Every `NGIT_GRASP_P_*` name written in `text`. A name cut short by a `*`
/// ends in `_`.
fn names_written(text: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        let from = &rest[start..];
        let end = from
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(from.len());
        names.insert(&from[..end]);
        rest = &from[end..];
    }
    names
}

/// One line for each name a file writes that is not a setting: what is left
/// behind when a setting is removed or renamed in the code alone.
fn unknown_names(settings: &[Setting], sources: Sources<'_>) -> Vec<String> {
    let known: BTreeSet<&str> = settings
        .iter()
        .map(|setting| setting.name.as_str())
        .collect();
    let mut problems = Vec::new();
    for (path, text) in [
        (REFERENCE, sources.reference),
        (ENV_EXAMPLE, sources.env_example),
        (NIX_MODULE, sources.nix_module),
    ] {
        for name in names_written(text) {
            if name.ends_with('_') {
                // `NGIT_GRASP_P_*`, or a family such as `NGIT_GRASP_P_MIRROR_*`.
                if !known.iter().any(|setting| setting.starts_with(name)) {
                    problems.push(format!(
                        "{path}: `{name}*` matches no setting in src/config.rs"
                    ));
                }
            } else if !known.contains(name) {
                problems.push(format!(
                    "{path}: names {name}, which is not a setting in src/config.rs"
                ));
            }
        }
    }
    problems
}

/// One line for each default that a file states differently from clap.
fn default_mismatches(settings: &[Setting], sources: Sources<'_>) -> Vec<String> {
    let env_lines: Vec<&str> = sources.env_example.lines().collect();
    let nix_lines: Vec<&str> = sources.nix_module.lines().collect();
    let mut problems = Vec::new();
    for setting in settings {
        let name = setting.name.as_str();
        let Some(default) = setting.default.as_deref() else {
            continue;
        };

        // A setting with no section at all is reported by `missing`.
        if let Some(section) = reference_section(sources.reference, name) {
            match reference_default(&section) {
                Some(stated) if stated == default => {}
                Some(stated) => problems.push(format!(
                    "{REFERENCE}: {name} documents the default `{stated}`; the code's default \
                     is `{default}`"
                )),
                None => problems.push(format!(
                    "{REFERENCE}: {name} gives no default in backticks on a `**Default:**` \
                     line; the code's default is `{default}`"
                )),
            }
        }

        // An empty default has nothing to show, so its line carries an
        // example instead.
        if !default.is_empty() {
            for (index, value) in env_assignments(&env_lines, name) {
                if value != default {
                    problems.push(format!(
                        "{ENV_EXAMPLE}: the line `{name}={value}` does not carry the code's \
                         default `{default}`"
                    ));
                }
                let stated = env_default_line(&env_lines, index);
                if let Some(stated) = stated.filter(|stated| stated.as_str() != default) {
                    problems.push(format!(
                        "{ENV_EXAMPLE}: {name} has `# Default: {stated}`; the code's default \
                         is `{default}`"
                    ));
                }
            }
        }

        let entry = nix_environment_entry(&nix_lines, name);
        if let Some(option) = entry.as_deref().and_then(nix_option_read) {
            let stated = nix_option_default(&nix_lines, option);
            if let Some(stated) = stated.filter(|stated| stated.as_str() != default) {
                problems.push(format!(
                    "{NIX_MODULE}: {name} is read from the option {option}, whose default is \
                     `{stated}`; the code's default is `{default}`"
                ));
            }
        }
    }
    problems
}

fn assert_none(problems: Vec<String>) {
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

/// `text` without the lines that write `name`.
fn without(text: &str, name: &str) -> String {
    text.lines()
        .filter(|line| !names_written(line).contains(name))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_grasp_p_setting_is_in_all_four_sources() {
    assert_none(missing(&settings(), Sources::real()));
}

#[test]
fn no_source_names_a_setting_the_code_lacks() {
    assert_none(unknown_names(&settings(), Sources::real()));
}

#[test]
fn documented_defaults_match_the_code() {
    assert_none(default_mismatches(&settings(), Sources::real()));
}

/// The three tests above pass on files that agree. This one shows that they
/// can fail: each setting in turn is taken out of each file in turn.
#[test]
fn a_setting_dropped_from_one_source_is_reported_for_that_source() {
    let settings = settings();
    let real = Sources::real();
    for setting in &settings {
        let name = setting.name.as_str();
        let reference = without(real.reference, name);
        let env_example = without(real.env_example, name);
        let nix_module = without(real.nix_module, name);
        for (path, sources) in [
            (
                REFERENCE,
                Sources {
                    reference: &reference,
                    ..real
                },
            ),
            (
                ENV_EXAMPLE,
                Sources {
                    env_example: &env_example,
                    ..real
                },
            ),
            (
                NIX_MODULE,
                Sources {
                    nix_module: &nix_module,
                    ..real
                },
            ),
        ] {
            let problems = missing(&settings, sources);
            assert!(
                !problems.is_empty(),
                "{name} was taken out of {path} and nothing was reported"
            );
            for problem in &problems {
                assert!(
                    problem.starts_with(path) && problem.contains(name),
                    "taking {name} out of {path} reported: {problem}"
                );
            }
        }
    }
}

/// A setting removed from the code alone leaves its name in the other three
/// files. Each one has to say so.
#[test]
fn a_setting_dropped_from_the_code_is_reported_for_every_source() {
    let settings = settings();
    for dropped in &settings {
        let name = dropped.name.as_str();
        let kept: Vec<Setting> = settings
            .iter()
            .filter(|setting| setting.name != dropped.name)
            .cloned()
            .collect();
        let problems = unknown_names(&kept, Sources::real());
        for path in [REFERENCE, ENV_EXAMPLE, NIX_MODULE] {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.starts_with(path) && problem.contains(name)),
                "{name} is not a setting any more and {path} was not reported: {problems:?}"
            );
        }
    }
}

/// Settings whose default in the code is not empty and whose NixOS option
/// does not state it as a plain value this module can read. None today. A
/// setting goes here, with the reason, when its option needs a list, `null`
/// or an expression; without this list its comparison would lapse unnoticed.
const NIX_DEFAULT_NOT_COMPARED: &[&str] = &[];

/// Each default that is not empty is changed in turn, in the code alone. The
/// reference and `.env.example` state every one, so both have to disagree
/// every time. So does the NixOS module, for every setting that is not
/// listed in `NIX_DEFAULT_NOT_COMPARED`.
#[test]
fn a_default_changed_in_the_code_is_reported() {
    for Setting { name, default } in settings() {
        let Some(default) = default.filter(|default| !default.is_empty()) else {
            continue;
        };
        let changed = Setting {
            name: name.clone(),
            default: Some(format!("{default}-changed")),
        };
        let problems = default_mismatches(&[changed], Sources::real());
        for path in [REFERENCE, ENV_EXAMPLE] {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.starts_with(path) && problem.contains(name.as_str())),
                "the default of {name} changed and {path} was not reported: {problems:?}"
            );
        }
        let compared = problems
            .iter()
            .any(|problem| problem.starts_with(NIX_MODULE));
        let listed = NIX_DEFAULT_NOT_COMPARED.contains(&name.as_str());
        assert!(
            compared || listed,
            "{NIX_MODULE}: the default of {name} is not compared. State it as a plain value, \
             or list the setting in NIX_DEFAULT_NOT_COMPARED with the reason"
        );
        assert!(
            !(compared && listed),
            "{NIX_MODULE}: the default of {name} is compared, so take it off \
             NIX_DEFAULT_NOT_COMPARED"
        );
    }
}

#[test]
fn only_plain_nix_values_are_compared() {
    for (value, read) in [
        ("true", Some("true")),
        ("false", Some("false")),
        ("2592000", Some("2592000")),
        ("\"whitelist\"", Some("whitelist")),
        ("\"\"", Some("")),
        ("null", None),
        ("[ ]", None),
        ("192 * 1024", None),
        ("\"ngit-grasp-${name}\"", None),
        ("", None),
    ] {
        assert_eq!(nix_literal(value).as_deref(), read, "{value:?}");
    }
}
