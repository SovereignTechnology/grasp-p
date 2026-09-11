//! Deterministic, source-owned CLI and runtime-configuration metadata.
//!
//! Stable Clap reflection supplies the command tree and environment-backed
//! options. The small registries below cover runtime validation and secret
//! precedence which Clap cannot expose through its stable reflection API.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use clap::{builder::ValueRange, Arg, ArgAction, Command, CommandFactory};
use serde::Serialize;

use super::Cli;

pub const INTERNAL_COMMAND: &str = "__docs-export";
const SCHEMA_VERSION: u32 = 1;
const PRODUCT_HOMEPAGE: &str = "https://ngit.dev";

#[derive(Serialize)]
struct DocsExport {
    schema_version: u32,
    capabilities: SchemaCapabilities,
    product: Product,
    invocation: Invocation,
    command: CommandDoc,
    configuration: Configuration,
}

#[derive(Serialize)]
struct SchemaCapabilities {
    argument_conflicts: bool,
    argument_groups: bool,
    conditional_requirements: bool,
    configuration_options: bool,
    configuration_constraints: bool,
    secret_sources: bool,
}

#[derive(Serialize)]
struct Product {
    id: &'static str,
    name: &'static str,
    version: &'static str,
    description: &'static str,
    homepage: &'static str,
    source_repository: &'static str,
    source_commit: Option<&'static str>,
}

#[derive(Serialize)]
struct Invocation {
    implicit_default_subcommand: &'static str,
    dotenv: DotenvBehavior,
}

#[derive(Serialize)]
struct DotenvBehavior {
    automatic: bool,
    overrides_process_environment: bool,
}

#[derive(Serialize)]
struct CommandDoc {
    id: String,
    name: String,
    path: Vec<String>,
    usage: String,
    about: Option<String>,
    long_about: Option<String>,
    before_help: Option<String>,
    after_help: Option<String>,
    aliases: Vec<AliasDoc>,
    hidden: bool,
    subcommand_required: bool,
    arg_required_else_help: bool,
    args: Vec<ArgDoc>,
    groups: Vec<ArgGroupDoc>,
    subcommands: Vec<Self>,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ArgDoc {
    id: String,
    name: String,
    kind: &'static str,
    short: Option<char>,
    long: Option<String>,
    aliases: Vec<ArgAliasDoc>,
    help: Option<String>,
    long_help: Option<String>,
    value_names: Vec<String>,
    action: &'static str,
    value_cardinality: Cardinality,
    repeatable: bool,
    required: bool,
    global: bool,
    hidden: bool,
    exclusive: bool,
    conflicts: Vec<String>,
    positional_index: Option<usize>,
    env: Option<String>,
    defaults: Vec<String>,
    possible_values: Vec<PossibleValueDoc>,
    value_delimiter: Option<char>,
    value_terminator: Option<String>,
    require_equals: bool,
    allow_hyphen_values: bool,
    allow_negative_numbers: bool,
    trailing_var_arg: bool,
    last: bool,
}

#[derive(Serialize)]
struct ArgGroupDoc {
    id: String,
    name: String,
    arguments: Vec<String>,
    required: bool,
    multiple: bool,
}

#[derive(Serialize)]
struct Cardinality {
    min: usize,
    max: Option<usize>,
}

#[derive(Serialize)]
struct AliasDoc {
    name: String,
    visible: bool,
}

#[derive(Serialize)]
struct ArgAliasDoc {
    name: String,
    kind: &'static str,
    visible: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct PossibleValueDoc {
    name: String,
    aliases: Vec<String>,
    help: Option<String>,
    hidden: bool,
}

#[derive(Serialize)]
struct Configuration {
    options: Vec<ConfigOptionDoc>,
    constraints: Vec<ConstraintDoc>,
    secret_sources: Vec<SecretSourceDoc>,
}

#[derive(Serialize)]
struct ConfigOptionDoc {
    id: String,
    env: String,
    arguments: Vec<String>,
    defaults: Vec<String>,
    possible_values: Vec<PossibleValueDoc>,
    scope: &'static str,
    sensitivity: &'static str,
    reload_behavior: &'static str,
    constraints: Vec<String>,
}

#[derive(Serialize)]
struct ConstraintDoc {
    id: String,
    kind: &'static str,
    description: &'static str,
    options: Vec<String>,
    details: ConstraintDetails,
}

#[derive(Serialize)]
#[serde(tag = "operator", rename_all = "snake_case")]
enum ConstraintDetails {
    Format,
    UniqueItems,
    GreaterThan { value: u64 },
    LessThanOrEqual { value: u64, unit: &'static str },
    MutuallyExclusive,
    Requires,
    RequiresAny,
    CheckedSum,
    Custom,
}

#[derive(Serialize)]
struct SecretSourceDoc {
    id: &'static str,
    option: String,
    precedence: u8,
    kind: &'static str,
    environment: Option<&'static str>,
    name: Option<&'static str>,
    path: Option<&'static str>,
    generates_if_missing: bool,
    description: &'static str,
}

struct ReflectedConfigOption {
    argument_ids: Vec<String>,
    defaults: Vec<String>,
    possible_values: Vec<PossibleValueDoc>,
    command_ids: BTreeSet<String>,
}

struct ConstraintSpec {
    id: &'static str,
    kind: &'static str,
    description: &'static str,
    envs: &'static [&'static str],
    details: ConstraintDetails,
}

pub fn write_stdout() -> Result<()> {
    let export = build()?;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &export)
        .context("failed to serialize documentation metadata")?;
    writer
        .write_all(b"\n")
        .context("failed to write documentation metadata")?;
    Ok(())
}

fn build() -> Result<DocsExport> {
    let mut command = Cli::command();
    command.build();
    let root = command_doc(&command, &[command.get_name().to_string()]);

    Ok(DocsExport {
        schema_version: SCHEMA_VERSION,
        capabilities: SchemaCapabilities {
            argument_conflicts: true,
            argument_groups: true,
            // Clap 4 has no stable reflection API for conditional requirements;
            // runtime-only relationships are exported as config constraints.
            conditional_requirements: false,
            configuration_options: true,
            configuration_constraints: true,
            secret_sources: true,
        },
        product: Product {
            id: env!("CARGO_PKG_NAME"),
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            description: env!("CARGO_PKG_DESCRIPTION"),
            homepage: PRODUCT_HOMEPAGE,
            source_repository: env!("CARGO_PKG_REPOSITORY"),
            source_commit: option_env!("NGIT_DOCS_SOURCE_COMMIT"),
        },
        invocation: Invocation {
            implicit_default_subcommand: "ngit-grasp.command.serve",
            dotenv: DotenvBehavior {
                automatic: true,
                // dotenvy::dotenv preserves variables already present in the
                // process environment.
                overrides_process_environment: false,
            },
        },
        configuration: configuration(&root)?,
        command: root,
    })
}

fn command_doc(command: &Command, path: &[String]) -> CommandDoc {
    let id = semantic_command_id(path);
    let mut usage_command = command.clone();
    let usage = usage_command.render_usage().to_string();

    let visible_aliases: Vec<_> = command.get_visible_aliases().collect();
    let mut aliases: Vec<_> = command
        .get_all_aliases()
        .map(|alias| AliasDoc {
            name: alias.to_string(),
            visible: visible_aliases.contains(&alias),
        })
        .collect();
    aliases.sort_by(|left, right| left.name.cmp(&right.name));

    let args = command
        .get_arguments()
        .map(|argument| arg_doc(command, argument, &id))
        .collect();
    let groups = group_docs(command, &id);
    let subcommands = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help")
        .map(|subcommand| {
            let mut subcommand_path = path.to_vec();
            subcommand_path.push(subcommand.get_name().to_string());
            command_doc(subcommand, &subcommand_path)
        })
        .collect();

    CommandDoc {
        id,
        name: command.get_name().to_string(),
        path: path.to_vec(),
        usage,
        about: styled(command.get_about()),
        long_about: styled(command.get_long_about()),
        before_help: styled(command.get_before_help()),
        after_help: styled(command.get_after_help()),
        aliases,
        hidden: command.is_hide_set(),
        subcommand_required: command.is_subcommand_required_set(),
        arg_required_else_help: command.is_arg_required_else_help_set(),
        args,
        groups,
        subcommands,
    }
}

fn arg_doc(command: &Command, argument: &Arg, command_id: &str) -> ArgDoc {
    let name = argument.get_id().as_str();
    let action = argument.get_action();
    let value_range = argument.get_num_args().unwrap_or_else(|| {
        if action.takes_values() {
            ValueRange::SINGLE
        } else {
            ValueRange::EMPTY
        }
    });
    let max = (value_range.max_values() != usize::MAX).then(|| value_range.max_values());

    ArgDoc {
        id: semantic_arg_id(command_id, name),
        name: name.to_string(),
        kind: if argument.get_index().is_some() {
            "positional"
        } else if action.takes_values() {
            "option"
        } else {
            "flag"
        },
        short: argument.get_short(),
        long: argument.get_long().map(ToString::to_string),
        aliases: arg_aliases(argument),
        help: styled(argument.get_help()),
        long_help: styled(argument.get_long_help()),
        value_names: argument
            .get_value_names()
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect(),
        action: action_name(action),
        value_cardinality: Cardinality {
            min: value_range.min_values(),
            max,
        },
        repeatable: matches!(action, ArgAction::Append | ArgAction::Count),
        required: argument.is_required_set(),
        global: argument.is_global_set(),
        hidden: argument.is_hide_set(),
        exclusive: argument.is_exclusive_set(),
        conflicts: arg_conflicts(command, argument, command_id),
        positional_index: argument.get_index(),
        env: argument
            .get_env()
            .map(|value| value.to_string_lossy().into_owned()),
        defaults: argument
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
        possible_values: possible_values(argument),
        value_delimiter: argument.get_value_delimiter(),
        value_terminator: argument.get_value_terminator().map(ToString::to_string),
        require_equals: argument.is_require_equals_set(),
        allow_hyphen_values: argument.is_allow_hyphen_values_set(),
        allow_negative_numbers: argument.is_allow_negative_numbers_set(),
        trailing_var_arg: argument.is_trailing_var_arg_set(),
        last: argument.is_last_set(),
    }
}

fn arg_conflicts(command: &Command, argument: &Arg, command_id: &str) -> Vec<String> {
    let argument_id = argument.get_id();
    let mut conflicts: Vec<_> = command
        .get_arguments()
        .filter(|candidate| candidate.get_id() != argument_id)
        .filter(|candidate| {
            command
                .get_arg_conflicts_with(argument)
                .iter()
                .any(|conflict| conflict.get_id() == candidate.get_id())
                || command
                    .get_arg_conflicts_with(candidate)
                    .iter()
                    .any(|conflict| conflict.get_id() == argument_id)
        })
        .map(|conflict| semantic_arg_id(command_id, conflict.get_id().as_str()))
        .collect();
    conflicts.sort();
    conflicts.dedup();
    conflicts
}

fn group_docs(command: &Command, command_id: &str) -> Vec<ArgGroupDoc> {
    let mut groups: Vec<_> = command
        .get_groups()
        .map(|group| {
            let name = group.get_id().as_str();
            let mut arguments: Vec<_> = group
                .get_args()
                .map(|argument| semantic_arg_id(command_id, argument.as_str()))
                .collect();
            arguments.sort();
            let mut group = group.clone();
            ArgGroupDoc {
                id: format!("{command_id}.group.{name}"),
                name: name.to_string(),
                arguments,
                required: group.is_required_set(),
                multiple: group.is_multiple(),
            }
        })
        .collect();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    groups
}

fn arg_aliases(argument: &Arg) -> Vec<ArgAliasDoc> {
    let visible_long = argument.get_visible_aliases().unwrap_or_default();
    let mut aliases: Vec<_> = argument
        .get_all_aliases()
        .unwrap_or_default()
        .into_iter()
        .map(|alias| ArgAliasDoc {
            name: alias.to_string(),
            kind: "long",
            visible: visible_long.contains(&alias),
        })
        .collect();
    let visible_short = argument.get_visible_short_aliases().unwrap_or_default();
    aliases.extend(
        argument
            .get_all_short_aliases()
            .unwrap_or_default()
            .into_iter()
            .map(|alias| ArgAliasDoc {
                name: alias.to_string(),
                kind: "short",
                visible: visible_short.contains(&alias),
            }),
    );
    aliases.sort_by(|left, right| {
        (left.kind, left.name.as_str()).cmp(&(right.kind, right.name.as_str()))
    });
    aliases
}

fn possible_values(argument: &Arg) -> Vec<PossibleValueDoc> {
    argument
        .get_possible_values()
        .into_iter()
        .map(|possible| {
            let name = possible.get_name();
            let mut aliases: Vec<_> = possible
                .get_name_and_aliases()
                .filter(|alias| *alias != name)
                .map(ToString::to_string)
                .collect();
            aliases.sort();
            PossibleValueDoc {
                name: name.to_string(),
                aliases,
                help: styled(possible.get_help()),
                hidden: possible.is_hide_set(),
            }
        })
        .collect()
}

fn configuration(root: &CommandDoc) -> Result<Configuration> {
    let mut reflected = BTreeMap::<String, ReflectedConfigOption>::new();
    collect_config_options(root, &mut reflected)?;

    // relay_owner_nsec is intentionally skipped by Clap so the secret can
    // never appear in argv. Add only its metadata, never a value.
    reflected.insert(
        "NGIT_RELAY_OWNER_NSEC".to_string(),
        ReflectedConfigOption {
            argument_ids: Vec::new(),
            defaults: Vec::new(),
            possible_values: Vec::new(),
            command_ids: BTreeSet::from(["ngit-grasp.command.serve".to_string()]),
        },
    );
    let specs = constraint_specs();
    let mut constraints_by_env = BTreeMap::<&str, Vec<String>>::new();
    let mut constraints = Vec::with_capacity(specs.len());
    for spec in specs {
        let constraint_id = config_constraint_id(spec.id);
        let mut options = Vec::with_capacity(spec.envs.len());
        for env in spec.envs {
            if !reflected.contains_key(*env) {
                bail!(
                    "configuration constraint {} references unknown {env}",
                    spec.id
                );
            }
            constraints_by_env
                .entry(env)
                .or_default()
                .push(constraint_id.clone());
            options.push(config_option_id(env));
        }
        constraints.push(ConstraintDoc {
            id: constraint_id,
            kind: spec.kind,
            description: spec.description,
            options,
            details: spec.details,
        });
    }

    let options = reflected
        .into_iter()
        .map(|(env, option)| {
            let scope = option_scope(&option.command_ids);
            ConfigOptionDoc {
                id: config_option_id(&env),
                sensitivity: if env == "NGIT_RELAY_OWNER_NSEC" {
                    "secret"
                } else {
                    "public"
                },
                env: env.clone(),
                arguments: option.argument_ids,
                defaults: option.defaults,
                possible_values: option.possible_values,
                scope,
                reload_behavior: "restart_required",
                constraints: constraints_by_env.remove(env.as_str()).unwrap_or_default(),
            }
        })
        .collect();

    let relay_owner_option = config_option_id("NGIT_RELAY_OWNER_NSEC");
    let secret_sources = vec![
        SecretSourceDoc {
            id: "ngit-grasp.secret-source.relay-owner.systemd-credential",
            option: relay_owner_option.clone(),
            precedence: 1,
            kind: "systemd_credential",
            environment: Some("CREDENTIALS_DIRECTORY"),
            name: Some("relay_owner_nsec"),
            path: None,
            generates_if_missing: false,
            description: "Read the relay_owner_nsec systemd credential when it exists.",
        },
        SecretSourceDoc {
            id: "ngit-grasp.secret-source.relay-owner.environment",
            option: relay_owner_option.clone(),
            precedence: 2,
            kind: "environment",
            environment: Some("NGIT_RELAY_OWNER_NSEC"),
            name: None,
            path: None,
            generates_if_missing: false,
            description: "Read the process environment, including an automatically loaded .env file; an existing process variable wins over .env.",
        },
        SecretSourceDoc {
            id: "ngit-grasp.secret-source.relay-owner.file",
            option: relay_owner_option,
            precedence: 3,
            kind: "file",
            environment: None,
            name: None,
            path: Some(".relay-owner.nsec"),
            generates_if_missing: true,
            description: "Read .relay-owner.nsec from the working directory, or generate it with owner-only permissions when absent.",
        },
    ];

    Ok(Configuration {
        options,
        constraints,
        secret_sources,
    })
}

fn collect_config_options(
    command: &CommandDoc,
    reflected: &mut BTreeMap<String, ReflectedConfigOption>,
) -> Result<()> {
    for argument in &command.args {
        let Some(env) = &argument.env else {
            continue;
        };
        let entry = reflected
            .entry(env.clone())
            .or_insert_with(|| ReflectedConfigOption {
                argument_ids: Vec::new(),
                defaults: argument.defaults.clone(),
                possible_values: argument.possible_values.clone(),
                command_ids: BTreeSet::new(),
            });
        if entry.defaults != argument.defaults
            || !same_possible_values(&entry.possible_values, &argument.possible_values)
        {
            bail!("shared environment variable {env} has inconsistent Clap metadata");
        }
        entry.argument_ids.push(argument.id.clone());
        entry.command_ids.insert(command.id.clone());
    }
    for subcommand in &command.subcommands {
        collect_config_options(subcommand, reflected)?;
    }
    Ok(())
}

fn same_possible_values(left: &[PossibleValueDoc], right: &[PossibleValueDoc]) -> bool {
    left == right
}

fn option_scope(command_ids: &BTreeSet<String>) -> &'static str {
    let serves = command_ids.contains("ngit-grasp.command.serve");
    let maintenance = command_ids
        .iter()
        .any(|id| id != "ngit-grasp.command.serve");
    match (serves, maintenance) {
        (true, true) => "shared",
        (true, false) => "serve",
        (false, true) => "maintenance",
        (false, false) => unreachable!("every configuration option has a scope"),
    }
}

fn constraint_specs() -> Vec<ConstraintSpec> {
    vec![
        constraint("relay-owner-key-format", "format", "The relay owner key must be a valid Nostr secret key.", &["NGIT_RELAY_OWNER_NSEC"], ConstraintDetails::Format),
        constraint("base-path-normalized", "format", "The base path must be '/' or a normalized absolute URL path without a trailing slash, empty segment, query, fragment, '.' or '..'.", &["NGIT_BASE_PATH"], ConstraintDetails::Format),
        constraint("bind-address-format", "format", "The bind address must be a valid IP address and port.", &["NGIT_BIND_ADDRESS"], ConstraintDetails::Format),
        constraint("startup-integrity-identifiers-valid", "format", "Every startup integrity identifier must be a valid repository identifier.", &["NGIT_STARTUP_INTEGRITY_IDENTIFIERS"], ConstraintDetails::Format),
        constraint("startup-integrity-identifiers-unique", "collection", "Startup integrity identifiers must not contain duplicates.", &["NGIT_STARTUP_INTEGRITY_IDENTIFIERS"], ConstraintDetails::UniqueItems),
        constraint("archive-services-with-archive-all", "relationship", "Archive GRASP services and archive-all mode are mutually exclusive.", &["NGIT_ARCHIVE_GRASP_SERVICES", "NGIT_ARCHIVE_ALL"], ConstraintDetails::MutuallyExclusive),
        constraint("archive-services-with-whitelist", "relationship", "Archive GRASP services and the archive whitelist are mutually exclusive.", &["NGIT_ARCHIVE_GRASP_SERVICES", "NGIT_ARCHIVE_WHITELIST"], ConstraintDetails::MutuallyExclusive),
        constraint("archive-read-only-requires-archive", "relationship", "Explicit read-only archive mode requires archive-all, an archive whitelist, or archive GRASP services.", &["NGIT_ARCHIVE_READ_ONLY", "NGIT_ARCHIVE_ALL", "NGIT_ARCHIVE_WHITELIST", "NGIT_ARCHIVE_GRASP_SERVICES"], ConstraintDetails::RequiresAny),
        constraint("private-mode-requires-members", "relationship", "Private mode requires at least one configured member.", &["NGIT_PRIVATE_MODE", "NGIT_PRIVATE_MEMBERS"], ConstraintDetails::Requires),
        constraint("private-members-require-mode", "relationship", "Configured private members require private mode.", &["NGIT_PRIVATE_MEMBERS", "NGIT_PRIVATE_MODE"], ConstraintDetails::Requires),
        constraint("private-mode-with-grasp06", "relationship", "Private mode and the unauthenticated GRASP-06 contributor endpoint are mutually exclusive.", &["NGIT_PRIVATE_MODE", "NGIT_GRASP06_ENABLE"], ConstraintDetails::MutuallyExclusive),
        constraint("private-members-format", "format", "Every private member must be a valid npub.", &["NGIT_PRIVATE_MEMBERS"], ConstraintDetails::Format),
        constraint("private-public-origin-format", "format", "The private public origin, when set, must be an absolute HTTP(S) origin without a path, query, or fragment.", &["NGIT_PRIVATE_PUBLIC_ORIGIN"], ConstraintDetails::Format),
        constraint("holding-retention-positive", "range", "Holding retention must be greater than zero seconds.", &["NGIT_HOLDING_RETENTION_SECS"], ConstraintDetails::GreaterThan { value: 0 }),
        constraint("holding-cleanup-interval-positive", "range", "The holding cleanup interval must be greater than zero seconds.", &["NGIT_HOLDING_CLEANUP_INTERVAL_SECS"], ConstraintDetails::GreaterThan { value: 0 }),
        constraint("sync-descendant-limit-positive", "range", "The recursive sync descendant limit must be greater than zero.", &["NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT"], ConstraintDetails::GreaterThan { value: 0 }),
        constraint("deletion-retention-durations-positive", "range", "Each deletion-request retention duration must be greater than zero seconds.", &["NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS", "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS", "NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS", "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS"], ConstraintDetails::GreaterThan { value: 0 }),
        constraint("unused-deletion-retention-sum", "arithmetic", "Unused served and additional gating durations must not overflow when combined.", &["NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS", "NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS"], ConstraintDetails::CheckedSum),
        constraint("used-deletion-retention-sum", "arithmetic", "Used served and additional gating durations must not overflow when combined.", &["NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS", "NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS"], ConstraintDetails::CheckedSum),
        constraint("relay-limits-positive", "range", "Relay subscription, event-size, and filter limits must each be greater than zero.", &["NGIT_RELAY_MAX_SUBSCRIPTIONS", "NGIT_RELAY_MAX_EVENT_SIZE_BYTES", "NGIT_RELAY_FILTER_LIMIT"], ConstraintDetails::GreaterThan { value: 0 }),
        constraint("relay-event-size-websocket-limit", "range", "The relay event-size limit must not exceed the 5 MiB WebSocket message limit.", &["NGIT_RELAY_MAX_EVENT_SIZE_BYTES"], ConstraintDetails::LessThanOrEqual { value: 5 * 1024 * 1024, unit: "bytes" }),
        constraint("repository-whitelist-with-read-only-archive", "relationship", "A repository whitelist cannot be used when effective archive read-only mode is true; read-only defaults to true whenever any archive mode is enabled.", &["NGIT_REPOSITORY_WHITELIST", "NGIT_ARCHIVE_READ_ONLY", "NGIT_ARCHIVE_ALL", "NGIT_ARCHIVE_WHITELIST", "NGIT_ARCHIVE_GRASP_SERVICES"], ConstraintDetails::Custom),
    ]
}

const fn constraint(
    id: &'static str,
    kind: &'static str,
    description: &'static str,
    envs: &'static [&'static str],
    details: ConstraintDetails,
) -> ConstraintSpec {
    ConstraintSpec {
        id,
        kind,
        description,
        envs,
        details,
    }
}

fn semantic_command_id(path: &[String]) -> String {
    format!(
        "ngit-grasp.command.{}",
        path.iter().skip(1).cloned().collect::<Vec<_>>().join(".")
    )
    .trim_end_matches('.')
    .to_string()
}

fn semantic_arg_id(command_id: &str, argument_name: &str) -> String {
    format!("{command_id}.argument.{argument_name}")
}

fn config_option_id(env: &str) -> String {
    format!("ngit-grasp.configuration.environment.{env}")
}

fn config_constraint_id(name: &str) -> String {
    format!("ngit-grasp.configuration.constraint.{name}")
}

fn action_name(action: &ArgAction) -> &'static str {
    match action {
        ArgAction::Set => "set",
        ArgAction::Append => "append",
        ArgAction::SetTrue => "set_true",
        ArgAction::SetFalse => "set_false",
        ArgAction::Count => "count",
        ArgAction::Help => "help",
        ArgAction::HelpShort => "help_short",
        ArgAction::HelpLong => "help_long",
        ArgAction::Version => "version",
        _ => "other",
    }
}

fn styled(value: Option<&clap::builder::StyledStr>) -> Option<String> {
    value.map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::Value;

    use super::*;

    fn json() -> String {
        serde_json::to_string_pretty(&build().unwrap()).unwrap()
    }

    fn command_at_path<'a>(root: &'a Value, path: &[&str]) -> &'a Value {
        let mut command = root;
        for name in path {
            command = command["subcommands"]
                .as_array()
                .unwrap()
                .iter()
                .find(|candidate| candidate["name"] == *name)
                .unwrap_or_else(|| panic!("command {name} missing"));
        }
        command
    }

    fn collect_ids(command: &Value, ids: &mut HashSet<String>, argument_ids: &mut HashSet<String>) {
        assert!(ids.insert(command["id"].as_str().unwrap().to_string()));
        assert!(command["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subcommand| subcommand["name"] != "help"));
        for argument in command["args"].as_array().unwrap() {
            assert!(argument_ids.insert(argument["id"].as_str().unwrap().to_string()));
        }
        for subcommand in command["subcommands"].as_array().unwrap() {
            collect_ids(subcommand, ids, argument_ids);
        }
    }

    #[test]
    fn export_is_deterministic() {
        assert_eq!(json(), json());
    }

    #[test]
    fn export_has_stable_schema_and_all_public_commands() {
        let export: Value = serde_json::from_str(&json()).unwrap();
        assert_eq!(export["schema_version"], SCHEMA_VERSION);
        assert_eq!(export["product"]["id"], "ngit-grasp");
        assert_eq!(export["command"]["id"], "ngit-grasp.command");
        assert_eq!(
            export["invocation"]["implicit_default_subcommand"],
            "ngit-grasp.command.serve"
        );
        assert_eq!(
            export["invocation"]["dotenv"]["overrides_process_environment"],
            false
        );

        let public_commands: Vec<_> = export["command"]["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|command| command["hidden"] == false)
            .map(|command| command["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            public_commands,
            [
                "serve",
                "cleanup-empty-repos",
                "holding-eject",
                "integrity-check"
            ]
        );
        assert!(command_at_path(&export["command"], &["serve"])["usage"]
            .as_str()
            .unwrap()
            .contains("ngit-grasp serve"));

        let mut command_ids = HashSet::new();
        let mut argument_ids = HashSet::new();
        collect_ids(&export["command"], &mut command_ids, &mut argument_ids);
    }

    #[test]
    fn configuration_groups_shared_envs_and_covers_every_reflected_env() {
        let export: Value = serde_json::from_str(&json()).unwrap();
        let options = export["configuration"]["options"].as_array().unwrap();
        let envs: HashSet<_> = options
            .iter()
            .map(|option| option["env"].as_str().unwrap())
            .collect();
        assert_eq!(envs.len(), options.len());
        assert!(envs.contains("NGIT_RELAY_OWNER_NSEC"));

        let git_data = options
            .iter()
            .find(|option| option["env"] == "NGIT_GIT_DATA_PATH")
            .unwrap();
        assert_eq!(git_data["scope"], "shared");
        assert_eq!(git_data["arguments"].as_array().unwrap().len(), 4);
        assert_eq!(git_data["defaults"], serde_json::json!(["./data/git"]));

        let database = options
            .iter()
            .find(|option| option["env"] == "NGIT_DATABASE_BACKEND")
            .unwrap();
        assert_eq!(
            database["possible_values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["lmdb", "memory"]
        );

        let mut reflected_envs = HashSet::new();
        fn collect(command: &Value, envs: &mut HashSet<String>) {
            for argument in command["args"].as_array().unwrap() {
                if let Some(env) = argument["env"].as_str() {
                    envs.insert(env.to_string());
                }
            }
            for subcommand in command["subcommands"].as_array().unwrap() {
                collect(subcommand, envs);
            }
        }
        collect(&export["command"], &mut reflected_envs);
        reflected_envs.insert("NGIT_RELAY_OWNER_NSEC".to_string());
        assert_eq!(envs, reflected_envs.iter().map(String::as_str).collect());
    }

    #[test]
    fn constraints_and_secret_precedence_have_valid_references() {
        let export: Value = serde_json::from_str(&json()).unwrap();
        let option_ids: HashSet<_> = export["configuration"]["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect();
        let constraint_ids: HashSet<_> = export["configuration"]["constraints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|constraint| constraint["id"].as_str().unwrap())
            .collect();
        let expected_constraint_ids = HashSet::from([
            "ngit-grasp.configuration.constraint.relay-owner-key-format",
            "ngit-grasp.configuration.constraint.base-path-normalized",
            "ngit-grasp.configuration.constraint.bind-address-format",
            "ngit-grasp.configuration.constraint.startup-integrity-identifiers-valid",
            "ngit-grasp.configuration.constraint.startup-integrity-identifiers-unique",
            "ngit-grasp.configuration.constraint.archive-services-with-archive-all",
            "ngit-grasp.configuration.constraint.archive-services-with-whitelist",
            "ngit-grasp.configuration.constraint.archive-read-only-requires-archive",
            "ngit-grasp.configuration.constraint.private-mode-requires-members",
            "ngit-grasp.configuration.constraint.private-members-require-mode",
            "ngit-grasp.configuration.constraint.private-mode-with-grasp06",
            "ngit-grasp.configuration.constraint.private-members-format",
            "ngit-grasp.configuration.constraint.private-public-origin-format",
            "ngit-grasp.configuration.constraint.holding-retention-positive",
            "ngit-grasp.configuration.constraint.holding-cleanup-interval-positive",
            "ngit-grasp.configuration.constraint.sync-descendant-limit-positive",
            "ngit-grasp.configuration.constraint.deletion-retention-durations-positive",
            "ngit-grasp.configuration.constraint.unused-deletion-retention-sum",
            "ngit-grasp.configuration.constraint.used-deletion-retention-sum",
            "ngit-grasp.configuration.constraint.relay-limits-positive",
            "ngit-grasp.configuration.constraint.relay-event-size-websocket-limit",
            "ngit-grasp.configuration.constraint.repository-whitelist-with-read-only-archive",
        ]);
        assert_eq!(constraint_ids, expected_constraint_ids);

        let archive_requires = export["configuration"]["constraints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|constraint| {
                constraint["id"]
                    == "ngit-grasp.configuration.constraint.archive-read-only-requires-archive"
            })
            .unwrap();
        assert_eq!(
            archive_requires["options"],
            serde_json::json!([
                "ngit-grasp.configuration.environment.NGIT_ARCHIVE_READ_ONLY",
                "ngit-grasp.configuration.environment.NGIT_ARCHIVE_ALL",
                "ngit-grasp.configuration.environment.NGIT_ARCHIVE_WHITELIST",
                "ngit-grasp.configuration.environment.NGIT_ARCHIVE_GRASP_SERVICES"
            ])
        );
        for constraint in export["configuration"]["constraints"].as_array().unwrap() {
            assert!(constraint["options"]
                .as_array()
                .unwrap()
                .iter()
                .all(|option| option_ids.contains(option.as_str().unwrap())));
        }
        for option in export["configuration"]["options"].as_array().unwrap() {
            assert!(option["constraints"]
                .as_array()
                .unwrap()
                .iter()
                .all(|constraint| constraint_ids.contains(constraint.as_str().unwrap())));
        }

        let sources = export["configuration"]["secret_sources"]
            .as_array()
            .unwrap();
        assert_eq!(
            sources
                .iter()
                .map(|source| source["precedence"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            sources
                .iter()
                .map(|source| source["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["systemd_credential", "environment", "file"]
        );
        assert!(sources.iter().all(|source| source["option"]
            == "ngit-grasp.configuration.environment.NGIT_RELAY_OWNER_NSEC"));
        assert!(!json().contains("secret_key"));
    }
}
