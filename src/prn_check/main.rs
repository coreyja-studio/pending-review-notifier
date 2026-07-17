//! `prn-check` — the standalone CLI mode of Pending Review Notifier
//! (docs/DESIGN.md "CLI mode"), for people who don't want to trust the hosted
//! service.
//!
//! Same detection logic as the service — it links [`discovery`] directly (the
//! GraphQL search, the age-basis and empty-shell rules, `is_stale`, and the
//! anti-flood `resolve_backlog`) — but authenticates with a classic Personal
//! Access Token from `GITHUB_TOKEN` and keeps its state in a local JSON file
//! instead of Postgres. No server, no OAuth, no database.
//!
//! Exit codes: 0 = nothing newly actionable, 1 = newly actionable pending
//! reviews exist, 2 = error. Designed for cron: `prn-check || notify-somehow`.

use std::path::PathBuf;
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use color_eyre::eyre::{Result, WrapErr, bail, eyre};

// Linked straight from the service source tree (not moved, per the
// architectural rule in src/discovery.rs: the discovery core is DB-free
// precisely so this binary can reuse it without the web/jobs stack).
#[path = "../discovery.rs"]
mod discovery;
mod state_file;

use state_file::{NOTIFY_DEDUP_DAYS, ReportItem, SweepOutcome};

/// Matches the service default (`users.threshold_hours` defaults to 3,
/// docs/DESIGN.md "Data model").
const DEFAULT_THRESHOLD_HOURS: i32 = 3;

/// GitHub requires a User-Agent on every API request.
const USER_AGENT: &str = "prn-check (pending-review-notifier CLI)";

const HELP: &str = "\
prn-check - find your own forgotten PENDING GitHub reviews

GitHub lets you leave review comments without submitting the review; they sit
PENDING, visible only to you, forever. prn-check finds yours, using only a
Personal Access Token and a local state file - no server involved.

USAGE:
    prn-check [OPTIONS]

AUTH:
    Reads a classic Personal Access Token from the GITHUB_TOKEN environment
    variable. Use the `repo` scope to cover private repositories
    (`public_repo` is enough for public-only).

OPTIONS:
    --threshold-hours <N>  Hours since the last activity on a pending review
                           before it counts as stale (default: 3, the same
                           default as the hosted service)
    --state-file <PATH>    Where to keep the local state
                           (default: $XDG_STATE_HOME/prn-check/state.json,
                           falling back to ~/.local/state/prn-check/state.json)
    --login <LOGIN>        GitHub login to check (default: the token's user)
    --json                 Emit machine-readable JSON instead of text
    --quiet                Only print newly actionable reviews; with cron's
                           MAILTO this means mail only when something alerts
    -h, --help             Show this help

EXIT CODES:
    0   nothing newly actionable
    1   newly actionable pending reviews exist
    2   error (bad usage, missing token, GitHub/network failure)

Reviews that are already stale the first time prn-check sees them are shown as
backlog but never alert; only reviews it watches cross the threshold do. Once
a review alerts, it will not alert again for 7 days — unless you comment on it
again, which starts a new cycle.
";

struct Args {
    threshold_hours: i32,
    state_file: PathBuf,
    json: bool,
    quiet: bool,
    login: Option<String>,
}

enum Cli {
    Run(Box<Args>),
    Help,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(Cli::Help) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Run(args)) => args,
        Err(error) => {
            eprintln!("prn-check: {error:#}");
            eprintln!("Run `prn-check --help` for usage.");
            return ExitCode::from(2);
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("prn-check: could not start async runtime: {error:#}");
            return ExitCode::from(2);
        }
    };

    match runtime.block_on(run(&args)) {
        Ok(true) => ExitCode::from(1),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("prn-check: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn parse_args(argv: &[String]) -> Result<Cli> {
    let mut threshold_hours = DEFAULT_THRESHOLD_HOURS;
    let mut state_file: Option<PathBuf> = None;
    let mut json = false;
    let mut quiet = false;
    let mut login: Option<String> = None;

    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        // Both `--flag value` and `--flag=value` are accepted.
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_string())),
            None => (arg.as_str(), None),
        };
        match flag {
            "--threshold-hours" => {
                let value = take_value(flag, inline, &mut iter)?;
                threshold_hours = value.parse().wrap_err_with(|| {
                    format!("--threshold-hours must be a number, got {value:?}")
                })?;
                if threshold_hours < 1 {
                    bail!("--threshold-hours must be at least 1");
                }
            }
            "--state-file" => {
                state_file = Some(PathBuf::from(take_value(flag, inline, &mut iter)?));
            }
            "--login" => login = Some(take_value(flag, inline, &mut iter)?),
            "--json" => {
                reject_value(flag, inline.as_deref())?;
                json = true;
            }
            "--quiet" => {
                reject_value(flag, inline.as_deref())?;
                quiet = true;
            }
            "-h" | "--help" => return Ok(Cli::Help),
            other => bail!("unknown argument {other:?}"),
        }
    }

    let state_file = match state_file {
        Some(path) => path,
        None => default_state_path()?,
    };

    Ok(Cli::Run(Box::new(Args {
        threshold_hours,
        state_file,
        json,
        quiet,
        login,
    })))
}

fn take_value(
    flag: &str,
    inline: Option<String>,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<String> {
    match inline {
        Some(value) => Ok(value),
        None => rest
            .next()
            .cloned()
            .ok_or_else(|| eyre!("{flag} requires a value")),
    }
}

fn reject_value(flag: &str, inline: Option<&str>) -> Result<()> {
    if inline.is_some() {
        bail!("{flag} does not take a value");
    }
    Ok(())
}

/// `$XDG_STATE_HOME/prn-check/state.json`, defaulting to
/// `~/.local/state/prn-check/state.json`.
fn default_state_path() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_STATE_HOME")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir).join("prn-check").join("state.json"));
    }
    let home = std::env::var("HOME")
        .map_err(|_| eyre!("HOME is not set; pass --state-file explicitly"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("prn-check")
        .join("state.json"))
}

async fn run(args: &Args) -> Result<bool> {
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            eyre!(
                "GITHUB_TOKEN is not set. Create a classic Personal Access Token \
                 (https://github.com/settings/tokens, `repo` scope for private \
                 repositories) and export it as GITHUB_TOKEN."
            )
        })?;

    // Overridable for tests and GitHub Enterprise (GITHUB_API_URL is the same
    // variable GitHub Actions exposes).
    let api_base = std::env::var("GITHUB_API_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string());

    let http = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .wrap_err("could not build HTTP client")?;

    let login = match &args.login {
        Some(login) => login.clone(),
        None => viewer_login(&http, &api_base, &token).await?,
    };

    let mut state = state_file::load(&args.state_file)?;
    let discovered = discovery::discover_pending_reviews(&http, &api_base, &token, &login).await?;

    let now = Utc::now();
    let outcome = state_file::apply_sweep(&mut state, &discovered, args.threshold_hours, now);

    if args.json {
        print_json(&outcome, &login, args.threshold_hours, now)?;
    } else {
        print_human(&outcome, args.threshold_hours, args.quiet, now);
    }

    // Save last: if the write fails after we printed, the next run re-alerts
    // (a duplicate beats a miss, same trade-off the service makes).
    state_file::save(&state, &args.state_file)?;

    Ok(!outcome.newly_actionable.is_empty())
}

/// Ask GitHub who the token belongs to — the search needs the login for both
/// the `involves:` qualifier and the review-author filter.
async fn viewer_login(http: &reqwest::Client, api_base: &str, token: &str) -> Result<String> {
    let response = http
        .post(format!("{api_base}/graphql"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "query": "query { viewer { login } }" }))
        .send()
        .await
        .wrap_err("could not reach the GitHub API")?
        .error_for_status()
        .wrap_err("GitHub rejected the request (is GITHUB_TOKEN valid?)")?;

    let body: serde_json::Value = response
        .json()
        .await
        .wrap_err("could not parse the viewer response")?;

    if let Some(errors) = body.get("errors").and_then(|e| e.as_array())
        && !errors.is_empty()
    {
        let joined = errors
            .iter()
            .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("GitHub viewer lookup returned errors: {joined}");
    }

    body.pointer("/data/viewer/login")
        .and_then(|login| login.as_str())
        .map(str::to_owned)
        .ok_or_else(|| eyre!("could not determine the token's GitHub login"))
}

fn print_json(
    outcome: &SweepOutcome,
    login: &str,
    threshold_hours: i32,
    now: DateTime<Utc>,
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct JsonOutput<'a> {
        checked_at: DateTime<Utc>,
        login: &'a str,
        threshold_hours: i32,
        #[serde(flatten)]
        outcome: &'a SweepOutcome,
    }

    let output = JsonOutput {
        checked_at: now,
        login,
        threshold_hours,
        outcome,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_human(outcome: &SweepOutcome, threshold_hours: i32, quiet: bool, now: DateTime<Utc>) {
    if outcome.newly_actionable.is_empty() {
        if !quiet {
            println!("No newly actionable pending reviews.");
        }
    } else {
        println!(
            "Newly actionable pending reviews ({}):",
            outcome.newly_actionable.len()
        );
        print_items(&outcome.newly_actionable, now);
    }

    if quiet {
        return;
    }

    if !outcome.snoozed.is_empty() {
        println!();
        println!(
            "Already reported ({}; re-alerts after {NOTIFY_DEDUP_DAYS} days):",
            outcome.snoozed.len()
        );
        print_items(&outcome.snoozed, now);
    }

    if !outcome.backlog.is_empty() {
        println!();
        println!(
            "Backlog ({}; already stale when first seen, never alerts):",
            outcome.backlog.len()
        );
        print_items(&outcome.backlog, now);
    }

    if !outcome.fresh.is_empty() {
        println!();
        println!(
            "Watching {} pending review(s) still under the {threshold_hours}h threshold.",
            outcome.fresh.len()
        );
    }
}

fn print_items(items: &[ReportItem], now: DateTime<Utc>) {
    for item in items {
        let comments = if item.comment_count == 1 {
            "1 comment".to_string()
        } else {
            format!("{} comments", item.comment_count)
        };
        println!("  {} - {}", item.repo_name_with_owner, item.pr_title);
        // Pending comments have no permalink; the /files tab shows them.
        println!(
            "    {}/files ({comments}, last activity {} ago)",
            item.pr_url,
            format_age(item.last_comment_at, now)
        );
    }
}

/// Human-readable age (e.g. "3d", "2w", "5h", "12m"), matching the service's
/// reminder email formatting.
fn format_age(last_comment_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let elapsed = now - last_comment_at;
    if elapsed.num_days() >= 7 {
        format!("{}w", elapsed.num_days() / 7)
    } else if elapsed.num_days() > 0 {
        format!("{}d", elapsed.num_days())
    } else if elapsed.num_hours() > 0 {
        format!("{}h", elapsed.num_hours())
    } else {
        format!("{}m", elapsed.num_minutes().max(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Result<Cli> {
        let argv: Vec<String> = argv.iter().map(ToString::to_string).collect();
        parse_args(&argv)
    }

    fn run_args(argv: &[&str]) -> Args {
        match args(argv).unwrap() {
            Cli::Run(args) => *args,
            Cli::Help => panic!("expected Run, got Help"),
        }
    }

    #[test]
    fn defaults_match_the_service() {
        let parsed = run_args(&["--state-file", "/tmp/s.json"]);
        assert_eq!(parsed.threshold_hours, DEFAULT_THRESHOLD_HOURS);
        assert!(!parsed.json);
        assert!(!parsed.quiet);
        assert!(parsed.login.is_none());
    }

    #[test]
    fn flags_parse_in_both_space_and_equals_forms() {
        let parsed = run_args(&[
            "--threshold-hours=24",
            "--state-file",
            "/tmp/s.json",
            "--login=coreyja",
            "--json",
            "--quiet",
        ]);
        assert_eq!(parsed.threshold_hours, 24);
        assert_eq!(parsed.state_file, PathBuf::from("/tmp/s.json"));
        assert_eq!(parsed.login.as_deref(), Some("coreyja"));
        assert!(parsed.json);
        assert!(parsed.quiet);
    }

    #[test]
    fn bad_arguments_are_rejected() {
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["--threshold-hours", "abc"]).is_err());
        assert!(args(&["--threshold-hours", "0"]).is_err());
        assert!(args(&["--threshold-hours"]).is_err());
        assert!(args(&["--json=true"]).is_err());
    }

    #[test]
    fn help_flag_wins() {
        assert!(matches!(args(&["--help"]).unwrap(), Cli::Help));
        assert!(matches!(args(&["-h"]).unwrap(), Cli::Help));
    }

    #[test]
    fn format_age_matches_the_reminder_email_style() {
        let now = DateTime::parse_from_rfc3339("2026-07-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(format_age(at("2026-07-01T12:00:00Z"), now), "2w");
        assert_eq!(format_age(at("2026-07-12T12:00:00Z"), now), "3d");
        assert_eq!(format_age(at("2026-07-15T07:00:00Z"), now), "5h");
        assert_eq!(format_age(at("2026-07-15T11:48:00Z"), now), "12m");
    }
}
