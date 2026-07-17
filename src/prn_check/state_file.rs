//! Local JSON state for `prn-check` — the CLI's stand-in for the service's
//! `pending_reviews` table (docs/DESIGN.md "CLI mode").
//!
//! Every classification rule delegates to [`crate::discovery`] so the CLI and
//! the service can never drift: staleness via [`discovery::is_stale`], the
//! anti-flood backlog rule via [`discovery::resolve_backlog`]. This module adds
//! only persistence and the 7-day notified-at dedup — the same rules the
//! service's `SyncUser`/`SendReminder` jobs apply against Postgres.
//!
//! [`apply_sweep`] is pure (state in, state out, injected `now`), so the whole
//! transition machine is testable without a network or filesystem.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use color_eyre::eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};

use crate::discovery::{self, DiscoveredReview};

/// Per-review re-alert window, matching the service's `SendReminder` dedup
/// (`notified_at IS NULL OR notified_at < now() - interval '7 days'`).
pub const NOTIFY_DEDUP_DAYS: i64 = 7;

/// The on-disk state file: one entry per pending review currently visible on
/// GitHub. Reviews that disappear (submitted or discarded) are reaped on the
/// next sweep, mirroring the service's `DELETE ... WHERE last_seen_at < sweep`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateFile {
    /// Format version, for forward compatibility. Currently always 1.
    #[serde(default = "version_one")]
    pub version: u32,
    /// Keyed by the review's GraphQL node id (`DiscoveredReview::review_id`).
    #[serde(default)]
    pub reviews: BTreeMap<String, ReviewState>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: version_one(),
            reviews: BTreeMap::new(),
        }
    }
}

fn version_one() -> u32 {
    1
}

/// What we remember about one pending review — the CLI equivalent of a
/// `pending_reviews` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewState {
    pub pr_url: String,
    pub pr_title: String,
    pub repo_name_with_owner: String,
    pub comment_count: i32,
    /// The staleness age basis (most recent comment, per discovery).
    pub last_comment_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
    /// The anti-flood flag: already stale the first time we ever saw it →
    /// shown but never actionable. Resolved by `discovery::resolve_backlog`.
    pub is_backlog: bool,
    /// Last time this review was reported actionable (the dedup stamp).
    pub notified_at: Option<DateTime<Utc>>,
}

/// One review as classified by a sweep, ready for human or JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportItem {
    pub review_id: String,
    pub pr_url: String,
    pub pr_title: String,
    pub repo_name_with_owner: String,
    pub comment_count: i32,
    pub last_comment_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
}

/// The result of one sweep. Each discovered review lands in exactly one list.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct SweepOutcome {
    /// Stale, non-backlog, and past the dedup window — these alert (exit 1)
    /// and get `notified_at` stamped.
    pub newly_actionable: Vec<ReportItem>,
    /// Stale and non-backlog, but reported within the last
    /// [`NOTIFY_DEDUP_DAYS`] days — shown, no alert.
    pub snoozed: Vec<ReportItem>,
    /// Already stale on first sight — shown, never alerts.
    pub backlog: Vec<ReportItem>,
    /// Under the threshold; being watched for a future crossing.
    pub fresh: Vec<ReportItem>,
}

/// Load the state file, treating a missing file as first-run empty state.
pub fn load(path: &Path) -> Result<StateFile> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).wrap_err_with(|| {
            format!("state file {} is not valid prn-check state", path.display())
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StateFile::default()),
        Err(error) => {
            Err(error).wrap_err_with(|| format!("could not read state file {}", path.display()))
        }
    }
}

/// Persist the state file atomically (write a sibling temp file, then rename),
/// creating parent directories as needed.
pub fn save(state: &StateFile, path: &Path) -> Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)
            .wrap_err_with(|| format!("could not create state directory {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(state).wrap_err("could not serialize state")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)
        .wrap_err_with(|| format!("could not write state file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .wrap_err_with(|| format!("could not move state file into place at {}", path.display()))?;
    Ok(())
}

/// Apply one sweep of discovered reviews to the state, mirroring the service's
/// `SyncUser` (upsert + backlog rule + reap) and `SendReminder` (staleness +
/// dedup + `notified_at` stamp) in a single pass:
///
/// - staleness: strict greater-than via [`discovery::is_stale`]
/// - backlog: [`discovery::resolve_backlog`] against the previously stored flag
/// - dedup: reviews reported actionable in the last [`NOTIFY_DEDUP_DAYS`] days
///   are snoozed, not re-alerted; newly-actionable ones get `notified_at = now`
/// - reap: entries not in `discovered` are dropped (gone from GitHub forever)
pub fn apply_sweep(
    state: &mut StateFile,
    discovered: &[DiscoveredReview],
    threshold_hours: i32,
    now: DateTime<Utc>,
) -> SweepOutcome {
    let mut next = BTreeMap::new();
    let mut outcome = SweepOutcome::default();

    for review in discovered {
        let previous = state.reviews.get(&review.review_id);
        let stale_now = discovery::is_stale(review.last_comment_at, threshold_hours, now);
        let is_backlog = discovery::resolve_backlog(previous.map(|p| p.is_backlog), stale_now);

        let mut entry = ReviewState {
            pr_url: review.pr_url.clone(),
            pr_title: review.pr_title.clone(),
            repo_name_with_owner: review.repo_name_with_owner.clone(),
            comment_count: review.comment_count,
            last_comment_at: review.last_comment_at,
            first_seen_at: previous.map_or(now, |p| p.first_seen_at),
            is_backlog,
            notified_at: previous.and_then(|p| p.notified_at),
        };

        let item = ReportItem {
            review_id: review.review_id.clone(),
            pr_url: entry.pr_url.clone(),
            pr_title: entry.pr_title.clone(),
            repo_name_with_owner: entry.repo_name_with_owner.clone(),
            comment_count: entry.comment_count,
            last_comment_at: entry.last_comment_at,
            first_seen_at: entry.first_seen_at,
        };

        if is_backlog {
            outcome.backlog.push(item);
        } else if !stale_now {
            outcome.fresh.push(item);
        } else if entry
            .notified_at
            .is_none_or(|at| at < now - Duration::days(NOTIFY_DEDUP_DAYS))
        {
            entry.notified_at = Some(now);
            outcome.newly_actionable.push(item);
        } else {
            outcome.snoozed.push(item);
        }

        next.insert(review.review_id.clone(), entry);
    }

    // Reap: anything not seen this sweep is gone from GitHub (submitted or
    // discarded), so it leaves the state file too.
    state.reviews = next;

    // Oldest-first within each section, matching the reminder email's ORDER BY
    // last_comment_at ASC; review_id breaks ties deterministically.
    for list in [
        &mut outcome.newly_actionable,
        &mut outcome.snoozed,
        &mut outcome.backlog,
        &mut outcome.fresh,
    ] {
        list.sort_by(|a, b| {
            a.last_comment_at
                .cmp(&b.last_comment_at)
                .then_with(|| a.review_id.cmp(&b.review_id))
        });
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn review(id: &str, last_comment_at: DateTime<Utc>) -> DiscoveredReview {
        DiscoveredReview {
            review_id: id.to_string(),
            pr_url: format!("https://github.com/o/r/pull/{id}"),
            pr_title: format!("PR {id}"),
            repo_name_with_owner: "o/r".to_string(),
            comment_count: 1,
            last_comment_at,
        }
    }

    fn ids(items: &[ReportItem]) -> Vec<&str> {
        items.iter().map(|i| i.review_id.as_str()).collect()
    }

    #[test]
    fn first_sight_stale_is_backlog_and_never_actionable() {
        let now = ts("2026-07-15T12:00:00Z");
        let mut state = StateFile::default();

        // 10h old against a 4h threshold, never seen before → backlog.
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", ts("2026-07-15T02:00:00Z"))],
            4,
            now,
        );

        assert_eq!(ids(&outcome.backlog), vec!["R1"]);
        assert!(outcome.newly_actionable.is_empty());
        assert!(outcome.snoozed.is_empty());
        assert!(outcome.fresh.is_empty());

        let entry = &state.reviews["R1"];
        assert!(entry.is_backlog);
        assert_eq!(entry.first_seen_at, now);
        assert!(entry.notified_at.is_none(), "backlog never gets stamped");
    }

    #[test]
    fn fresh_review_that_crosses_threshold_becomes_actionable() {
        let last_comment_at = ts("2026-07-15T11:00:00Z");
        let mut state = StateFile::default();

        // First sweep: 1h old against a 4h threshold → fresh, watched.
        let first_sweep = ts("2026-07-15T12:00:00Z");
        let outcome = apply_sweep(&mut state, &[review("R1", last_comment_at)], 4, first_sweep);
        assert_eq!(ids(&outcome.fresh), vec!["R1"]);
        assert!(!state.reviews["R1"].is_backlog);

        // Second sweep 6h later: now 7h old → we watched it cross → actionable.
        let second_sweep = ts("2026-07-15T18:00:00Z");
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", last_comment_at)],
            4,
            second_sweep,
        );
        assert_eq!(ids(&outcome.newly_actionable), vec!["R1"]);

        let entry = &state.reviews["R1"];
        assert_eq!(entry.notified_at, Some(second_sweep), "dedup stamp set");
        assert_eq!(entry.first_seen_at, first_sweep, "first sight preserved");
    }

    #[test]
    fn exactly_at_threshold_is_not_yet_stale() {
        // Strict greater-than, matching discovery::is_stale: exactly 4h old
        // against a 4h threshold is still fresh.
        let now = ts("2026-07-15T12:00:00Z");
        let mut state = StateFile::default();
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", ts("2026-07-15T08:00:00Z"))],
            4,
            now,
        );
        assert_eq!(ids(&outcome.fresh), vec!["R1"]);
        assert!(outcome.backlog.is_empty());
    }

    #[test]
    fn notified_reviews_are_snoozed_for_seven_days() {
        let last_comment_at = ts("2026-07-01T00:00:00Z");
        let mut state = StateFile::default();

        // Watched fresh, then crossed the threshold → actionable once.
        apply_sweep(
            &mut state,
            &[review("R1", last_comment_at)],
            4,
            ts("2026-07-01T01:00:00Z"),
        );
        let notified_at = ts("2026-07-01T08:00:00Z");
        let outcome = apply_sweep(&mut state, &[review("R1", last_comment_at)], 4, notified_at);
        assert_eq!(ids(&outcome.newly_actionable), vec!["R1"]);

        // 6 days later: inside the dedup window → snoozed, not re-alerted.
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", last_comment_at)],
            4,
            ts("2026-07-07T08:00:00Z"),
        );
        assert_eq!(ids(&outcome.snoozed), vec!["R1"]);
        assert!(outcome.newly_actionable.is_empty());
        assert_eq!(
            state.reviews["R1"].notified_at,
            Some(notified_at),
            "snoozing must not refresh the stamp"
        );

        // Just past 7 days: eligible again, and the stamp is refreshed.
        let re_alert = ts("2026-07-08T08:00:01Z");
        let outcome = apply_sweep(&mut state, &[review("R1", last_comment_at)], 4, re_alert);
        assert_eq!(ids(&outcome.newly_actionable), vec!["R1"]);
        assert_eq!(state.reviews["R1"].notified_at, Some(re_alert));
    }

    #[test]
    fn backlog_clears_when_seen_fresh_and_can_later_alert() {
        let mut state = StateFile::default();

        // First sight already stale → backlog.
        apply_sweep(
            &mut state,
            &[review("R1", ts("2026-07-14T00:00:00Z"))],
            4,
            ts("2026-07-15T12:00:00Z"),
        );
        assert!(state.reviews["R1"].is_backlog);

        // A new comment revives it: seen fresh → backlog clears.
        let revived_at = ts("2026-07-15T13:00:00Z");
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", revived_at)],
            4,
            ts("2026-07-15T13:30:00Z"),
        );
        assert_eq!(ids(&outcome.fresh), vec!["R1"]);
        assert!(!state.reviews["R1"].is_backlog);

        // We are watching it now, so its next crossing is actionable.
        let outcome = apply_sweep(
            &mut state,
            &[review("R1", revived_at)],
            4,
            ts("2026-07-15T20:00:00Z"),
        );
        assert_eq!(ids(&outcome.newly_actionable), vec!["R1"]);
    }

    #[test]
    fn unseen_reviews_are_reaped() {
        let mut state = StateFile::default();
        let seen_at = ts("2026-07-15T12:00:00Z");
        apply_sweep(
            &mut state,
            &[
                review("R1", ts("2026-07-15T11:00:00Z")),
                review("R2", ts("2026-07-15T11:00:00Z")),
            ],
            4,
            seen_at,
        );
        assert_eq!(state.reviews.len(), 2);

        // R2 was submitted or discarded → gone from GitHub → reaped here.
        apply_sweep(
            &mut state,
            &[review("R1", ts("2026-07-15T11:00:00Z"))],
            4,
            ts("2026-07-15T12:30:00Z"),
        );
        assert_eq!(
            state.reviews.keys().collect::<Vec<_>>(),
            vec!["R1"],
            "R2 reaped, R1 kept"
        );
    }

    #[test]
    fn sections_are_sorted_oldest_first() {
        let now = ts("2026-07-15T12:00:00Z");
        let mut state = StateFile::default();
        let outcome = apply_sweep(
            &mut state,
            &[
                review("R_NEWER", ts("2026-07-15T02:00:00Z")),
                review("R_OLDER", ts("2026-07-14T02:00:00Z")),
            ],
            4,
            now,
        );
        assert_eq!(ids(&outcome.backlog), vec!["R_OLDER", "R_NEWER"]);
    }

    #[test]
    fn load_missing_file_is_first_run_empty_state() {
        let path = std::env::temp_dir().join(format!(
            "prn-check-test-{}/state.json",
            uuid::Uuid::new_v4()
        ));
        let state = load(&path).unwrap();
        assert_eq!(state.reviews.len(), 0);
    }

    #[test]
    fn save_then_load_round_trips_and_creates_directories() {
        let dir = std::env::temp_dir().join(format!("prn-check-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("nested/state.json");

        let mut state = StateFile::default();
        apply_sweep(
            &mut state,
            &[review("R1", ts("2026-07-15T11:00:00Z"))],
            4,
            ts("2026-07-15T12:00:00Z"),
        );
        save(&state, &path).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.reviews, state.reviews);
        assert_eq!(loaded.version, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rejects_corrupt_state_instead_of_silently_resetting() {
        // A corrupt file must not be treated as first-run: that would wipe
        // first-seen history and re-classify everything as backlog.
        let dir = std::env::temp_dir().join(format!("prn-check-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("state.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        assert!(load(&path).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
