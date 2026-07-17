use chrono::Utc;
use cja::jobs::Job;
use maud::{DOCTYPE, html};
use uuid::Uuid;

use crate::{discovery, github::oauth, state::AppState};

/// Sync one user's pending reviews into `pending_reviews`.
///
/// Steps (docs/DESIGN.md "Jobs & scheduling"): ensure a fresh token (refreshing
/// and rotating if near expiry) → paginate discovery → upsert every seen review
/// → reap rows not seen in this sweep. Idempotent; the initial post-signup sync
/// is the same job.
///
/// Error handling: any `Err` returned here is caught by cja's job worker and
/// retried with exponential backoff (dead-lettered after max retries) — it does
/// NOT crash the app. A transient GitHub failure surfaces as an error precisely
/// so the row set is left untouched instead of being reaped to empty.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncUser {
    pub user_id: Uuid,
}

#[async_trait::async_trait]
impl Job<AppState> for SyncUser {
    const NAME: &'static str = "SyncUser";

    async fn run(&self, state: AppState) -> cja::Result<()> {
        // Refreshes + rotates the token if it is near expiry; on a definitive
        // GitHub rejection this marks the user needs_reauth and errors out.
        let access_token = oauth::ensure_fresh_token(&state, self.user_id).await?;

        let user = sqlx::query!(
            "SELECT github_login, threshold_hours FROM users WHERE user_id = $1",
            self.user_id
        )
        .fetch_one(&state.db)
        .await?;

        let reviews = discovery::discover_pending_reviews(
            &state.http,
            &state.config.github_api_base,
            &access_token,
            &user.github_login,
        )
        .await?;

        // The backlog rule needs each review's previously stored flag. Read
        // them all in one query up front (not per-review) so the anti-flood
        // decision stays in `discovery::resolve_backlog` — the single source of
        // truth the CLI will reuse — rather than being re-encoded in SQL.
        let previous_backlog: std::collections::HashMap<String, bool> = sqlx::query!(
            "SELECT review_id, is_backlog FROM pending_reviews WHERE user_id = $1",
            self.user_id
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|row| (row.review_id, row.is_backlog))
        .collect();

        // One timestamp for the whole sweep: every upserted row is stamped with
        // it, and anything left older than it (i.e. not seen this pass) is
        // reaped. Capturing it once avoids a row straddling the boundary.
        let sweep_at = Utc::now();

        for review in &reviews {
            let stale_now =
                discovery::is_stale(review.last_comment_at, user.threshold_hours, sweep_at);
            let is_backlog = discovery::resolve_backlog(
                previous_backlog.get(&review.review_id).copied(),
                stale_now,
            );

            sqlx::query!(
                "INSERT INTO pending_reviews (
                    review_id, user_id, pr_url, pr_title, repo_name_with_owner,
                    comment_count, last_comment_at, last_seen_at, is_backlog
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (review_id, user_id) DO UPDATE SET
                    pr_url = EXCLUDED.pr_url,
                    pr_title = EXCLUDED.pr_title,
                    repo_name_with_owner = EXCLUDED.repo_name_with_owner,
                    comment_count = EXCLUDED.comment_count,
                    last_comment_at = EXCLUDED.last_comment_at,
                    last_seen_at = EXCLUDED.last_seen_at,
                    is_backlog = EXCLUDED.is_backlog",
                review.review_id,
                self.user_id,
                review.pr_url,
                review.pr_title,
                review.repo_name_with_owner,
                review.comment_count,
                review.last_comment_at,
                sweep_at,
                is_backlog,
            )
            .execute(&state.db)
            .await?;
        }

        // Reap rows not seen this sweep: a submitted or discarded review is gone
        // from GitHub forever, so it should leave the dashboard too.
        let reaped = sqlx::query!(
            "DELETE FROM pending_reviews WHERE user_id = $1 AND last_seen_at < $2",
            self.user_id,
            sweep_at
        )
        .execute(&state.db)
        .await?
        .rows_affected();

        tracing::info!(
            user_id = %self.user_id,
            discovered = reviews.len(),
            reaped,
            "SyncUser completed"
        );

        Ok(())
    }
}

// NB: cja's job worker looks up handlers by the NAME string. Renaming
// SendDigest → SendReminder orphans any `SendDigest` rows still enqueued at
// deploy time — accepted: they only ever exist within one 15-minute sweep
// window, and the next ReminderSweep re-covers the same reviews.
cja::impl_job_registry!(AppState, SyncUser, SendReminder);

/// A pending-review row selected for the reminder email.
///
/// All columns are `NOT NULL`, so fields are non-`Option`.
struct ReminderReviewRow {
    id: Uuid,
    pr_title: String,
    repo_name_with_owner: String,
    pr_url: String,
    comment_count: i32,
    last_comment_at: chrono::DateTime<chrono::Utc>,
}

/// Send a reminder email for a user's email-eligible pending reviews.
///
/// Enqueued for every active user each 15-minute `ReminderSweep` tick, so a
/// review is emailed at the first tick after it crosses the threshold — with a
/// 3h threshold, a comment at 2pm means a reminder at ~5pm. No daily gating:
/// the timing follows when the user actually left comments.
///
/// Selects rows where `is_backlog = false`, `dismissed_at IS NULL`, the staleness
/// threshold is exceeded (strict `>`, matching `discovery::is_stale`), and the
/// per-review dedup (`notified_at`) allows re-nagging after 7 days. That dedup
/// is also what makes the every-tick enqueue safe: once a review is emailed,
/// the next tick's run selects nothing and sends nothing.
///
/// If rows match, sends ONE email per user per tick (batching everything that
/// newly qualified, capped at 20 items) and stamps `notified_at` on each.
///
/// Retry semantics: if the job dies after `mailer.send` but before the stamps,
/// a retry re-sends (duplicate email) — accepted (a dup beats a miss). Job
/// `Err` is caught by the worker (retry/backoff), never crashes the app.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendReminder {
    pub user_id: Uuid,
}

#[async_trait::async_trait]
impl Job<AppState> for SendReminder {
    const NAME: &'static str = "SendReminder";

    async fn run(&self, state: AppState) -> cja::Result<()> {
        let Some(user) = sqlx::query!(
            "SELECT threshold_hours, email FROM users WHERE user_id = $1 AND status = 'active'",
            self.user_id
        )
        .fetch_optional(&state.db)
        .await?
        else {
            return Ok(());
        };

        let reviews = sqlx::query_as!(
            ReminderReviewRow,
            "SELECT id, pr_title, repo_name_with_owner, pr_url, comment_count, last_comment_at
             FROM pending_reviews
             WHERE user_id = $1
               AND is_backlog = false
               AND dismissed_at IS NULL
               AND now() - last_comment_at > make_interval(hours => $2)
               AND (notified_at IS NULL OR notified_at < now() - interval '7 days')
             ORDER BY last_comment_at ASC
             LIMIT 20",
            self.user_id,
            user.threshold_hours,
        )
        .fetch_all(&state.db)
        .await?;

        if reviews.is_empty() {
            return Ok(());
        }

        // Honest subject: the count and the fact, no brackets, no decoration.
        let subject = if reviews.len() == 1 {
            "1 pending review needs a nudge".to_string()
        } else {
            format!("{} pending reviews need a nudge", reviews.len())
        };

        let html_body = render_reminder_email(&reviews, user.threshold_hours);
        state.mailer.send(&user.email, &subject, &html_body).await?;

        let ids: Vec<Uuid> = reviews.iter().map(|r| r.id).collect();
        sqlx::query!(
            "UPDATE pending_reviews SET notified_at = now() WHERE id = ANY($1)",
            &ids
        )
        .execute(&state.db)
        .await?;

        tracing::info!(
            user_id = %self.user_id,
            review_count = reviews.len(),
            "SendReminder: email sent"
        );

        Ok(())
    }
}

/// Human-readable age from `last_comment_at` to now (e.g. "3d", "2w", "5h", "12m").
fn format_age(last_comment_at: chrono::DateTime<chrono::Utc>) -> String {
    let elapsed = chrono::Utc::now() - last_comment_at;
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

/// Email-safe font stack, repeated inline on every text-bearing element
/// (email clients strip `<style>`/external CSS).
const EMAIL_FONT: &str =
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";

/// Render the reminder email HTML body. Table-based layout, all styles inline.
/// Auto-escaped text (no `PreEscaped` on `pr_title`/`repo_name_with_owner`).
///
/// Dark-mode tolerance: explicit `color-scheme` metas, no `background-color`
/// anywhere (the client supplies it), no pure #000/#fff, and a bordered — not
/// filled — CTA so forced inversion can't produce black-on-black.
fn render_reminder_email(reviews: &[ReminderReviewRow], threshold_hours: i32) -> String {
    let lede = if reviews.len() == 1 {
        "You left a pending review hanging.".to_string()
    } else {
        format!("You left {} pending reviews hanging.", reviews.len())
    };
    // Rows are ordered oldest-first, so the first row is the preheader's hook.
    let preheader = reviews.first().map(|oldest| {
        format!(
            "{} — oldest: {}, {}.",
            if reviews.len() == 1 {
                "1 pending review needs a nudge".to_string()
            } else {
                format!("{} pending reviews need a nudge", reviews.len())
            },
            oldest.repo_name_with_owner,
            format_age(oldest.last_comment_at),
        )
    });

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light dark";
                meta name="supported-color-schemes" content="light dark";
                title { "Pending Review Notifier" }
            }
            body style="margin: 0; padding: 0;" {
                @if let Some(preheader) = preheader {
                    div style="display: none; max-height: 0; overflow: hidden;" { (preheader) }
                }
                table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                    style="border-collapse: collapse; border-top: 6px solid #1a1a1a;" {
                    tr {
                        td align="center" style="padding: 24px 16px 40px;" {
                            table role="presentation" cellpadding="0" cellspacing="0"
                                style="border-collapse: collapse; max-width: 560px; width: 100%;" {
                                tr {
                                    td style=(format!("font-family: {EMAIL_FONT}; font-size: 13px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #595959; padding: 0 0 16px;")) {
                                        "Pending Review Notifier"
                                    }
                                }
                                tr {
                                    td style=(format!("font-family: {EMAIL_FONT}; font-size: 20px; font-weight: 700; line-height: 1.3; color: #1a1a1a; padding: 0 0 10px;")) {
                                        (lede)
                                    }
                                }
                                @for review in reviews {
                                    tr {
                                        td style=(format!("font-family: {EMAIL_FONT}; padding: 14px 0; border-top: 1px solid #d4d4d4;")) {
                                            a href=(format!("{}/files", review.pr_url))
                                                style=(format!("font-family: {EMAIL_FONT}; font-size: 16px; font-weight: 700; color: #0000ee; text-decoration: underline;")) {
                                                (review.pr_title)
                                            }
                                            div style=(format!("font-family: {EMAIL_FONT}; font-size: 14px; color: #595959; padding-top: 2px;")) {
                                                (review.repo_name_with_owner)
                                                " · " (review.comment_count)
                                                @if review.comment_count == 1 { " comment" } @else { " comments" }
                                                " · "
                                                span style="color: #b30000; font-weight: 700;" {
                                                    (format_age(review.last_comment_at))
                                                }
                                                " since last comment"
                                            }
                                        }
                                    }
                                }
                                tr {
                                    td style="padding: 24px 0;" {
                                        a href="https://prn.coreyja.studio/dashboard"
                                            style=(format!("font-family: {EMAIL_FONT}; display: inline-block; padding: 10px 20px; border: 2px solid #1a1a1a; font-size: 14px; font-weight: 700; color: #1a1a1a; text-decoration: none;")) {
                                            "Open dashboard"
                                        }
                                    }
                                }
                                tr {
                                    td style=(format!("font-family: {EMAIL_FONT}; font-size: 13px; line-height: 1.4; color: #8a8a8a; padding: 16px 0 0; border-top: 1px solid #d4d4d4;")) {
                                        "You get this because a pending review sat untouched for more than "
                                        (threshold_hours) " hours after your last comment. Change the threshold or unsubscribe in "
                                        a href="https://prn.coreyja.studio/settings" style="color: #8a8a8a;" { "Settings" }
                                        "."
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    .into_string()
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use sqlx::PgPool;
    use std::sync::Arc;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    use super::*;
    use crate::state::test_support::{test_config, test_state};

    /// Insert an active user with a far-future token expiry so `SyncUser` never
    /// needs to hit the refresh endpoint (keeps the mock surface to /graphql).
    async fn insert_active_user(state: &AppState, threshold_hours: i32) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email, threshold_hours
            )
            VALUES ($1, 'coreyja', 12345, $2, $3, $4, 'corey@example.com', $5)",
            user_id,
            state
                .crypto
                .encrypt("gho_access", user_id.as_bytes())
                .unwrap(),
            state
                .crypto
                .encrypt("ghr_refresh", user_id.as_bytes())
                .unwrap(),
            Utc::now() + Duration::days(30),
            threshold_hours,
        )
        .execute(&state.db)
        .await
        .unwrap();
        user_id
    }

    /// Mount a single-page search response returning the given search nodes.
    async fn mount_search(mock: &MockServer, nodes: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_string_contains("involves:"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "search": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": nodes
                    }
                }
            })))
            .mount(mock)
            .await;
    }

    fn pr_node(
        url: &str,
        review_id: &str,
        comment_at: DateTime<Utc>,
        total: i32,
    ) -> serde_json::Value {
        let comment_nodes = if total > 0 {
            serde_json::json!([{ "createdAt": comment_at.to_rfc3339() }])
        } else {
            serde_json::json!([])
        };
        serde_json::json!({
            "__typename": "PullRequest",
            "url": url,
            "title": "Some PR",
            "repository": { "nameWithOwner": "o/r" },
            "reviews": { "nodes": [{
                "id": review_id,
                "createdAt": comment_at.to_rfc3339(),
                "comments": { "totalCount": total, "nodes": comment_nodes }
            }]}
        })
    }

    fn state_pointing_at(mock: &MockServer, db: PgPool) -> AppState {
        let mut config = test_config();
        config.github_api_base = mock.uri();
        test_state(db, config)
    }

    #[sqlx::test]
    async fn sync_inserts_and_applies_backlog_rule(db: PgPool) {
        let mock = MockServer::start().await;
        let state = state_pointing_at(&mock, db.clone());
        let user_id = insert_active_user(&state, 4).await;

        // One stale review (10h old > 4h threshold → backlog), one fresh review
        // (1h old → email-eligible), one empty shell (skipped).
        let stale_at = Utc::now() - Duration::hours(10);
        let fresh_at = Utc::now() - Duration::hours(1);
        mount_search(
            &mock,
            serde_json::json!([
                pr_node("https://github.com/o/r/pull/1", "R_STALE", stale_at, 2),
                pr_node("https://github.com/o/r/pull/2", "R_FRESH", fresh_at, 1),
                pr_node("https://github.com/o/r/pull/3", "R_EMPTY", Utc::now(), 0),
            ]),
        )
        .await;

        SyncUser { user_id }.run(state.clone()).await.unwrap();

        let rows = sqlx::query!(
            "SELECT review_id, is_backlog FROM pending_reviews WHERE user_id = $1 ORDER BY review_id",
            user_id
        )
        .fetch_all(&db)
        .await
        .unwrap();

        assert_eq!(rows.len(), 2, "empty shell must be skipped");
        assert_eq!(rows[0].review_id, "R_FRESH");
        assert!(!rows[0].is_backlog, "fresh-on-first-sight is not backlog");
        assert_eq!(rows[1].review_id, "R_STALE");
        assert!(rows[1].is_backlog, "stale-on-first-sight is backlog");
    }

    #[sqlx::test]
    async fn backlog_clears_when_a_review_is_seen_fresh_again(db: PgPool) {
        // First sweep: a stale review → backlog.
        let mock = MockServer::start().await;
        let state = state_pointing_at(&mock, db.clone());
        let user_id = insert_active_user(&state, 4).await;
        mount_search(
            &mock,
            serde_json::json!([pr_node(
                "https://github.com/o/r/pull/1",
                "R1",
                Utc::now() - Duration::hours(10),
                1
            )]),
        )
        .await;
        SyncUser { user_id }.run(state).await.unwrap();

        let backlog: bool =
            sqlx::query_scalar!("SELECT is_backlog FROM pending_reviews WHERE review_id = 'R1'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(backlog, "first sight stale → backlog");

        // Second sweep: same review now fresh (a new comment landed) → backlog
        // clears and it re-enters the email lifecycle. Fresh mock server.
        let mock = MockServer::start().await;
        let state = state_pointing_at(&mock, db.clone());
        mount_search(
            &mock,
            serde_json::json!([pr_node(
                "https://github.com/o/r/pull/1",
                "R1",
                Utc::now() - Duration::minutes(5),
                2
            )]),
        )
        .await;
        SyncUser { user_id }.run(state).await.unwrap();

        let backlog: bool =
            sqlx::query_scalar!("SELECT is_backlog FROM pending_reviews WHERE review_id = 'R1'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(!backlog, "seen fresh again → backlog cleared");
    }

    #[sqlx::test]
    async fn reap_deletes_reviews_not_seen_this_sweep(db: PgPool) {
        let mock = MockServer::start().await;
        let state = state_pointing_at(&mock, db.clone());
        let user_id = insert_active_user(&state, 4).await;
        mount_search(
            &mock,
            serde_json::json!([
                pr_node(
                    "https://github.com/o/r/pull/1",
                    "R1",
                    Utc::now() - Duration::hours(1),
                    1
                ),
                pr_node(
                    "https://github.com/o/r/pull/2",
                    "R2",
                    Utc::now() - Duration::hours(1),
                    1
                ),
            ]),
        )
        .await;
        SyncUser { user_id }.run(state).await.unwrap();

        assert_eq!(
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM pending_reviews WHERE user_id = $1",
                user_id
            )
            .fetch_one(&db)
            .await
            .unwrap(),
            Some(2)
        );

        // Second sweep only returns R1; R2 was submitted/discarded → reaped.
        let mock = MockServer::start().await;
        let state = state_pointing_at(&mock, db.clone());
        mount_search(
            &mock,
            serde_json::json!([pr_node(
                "https://github.com/o/r/pull/1",
                "R1",
                Utc::now() - Duration::hours(1),
                1
            )]),
        )
        .await;
        SyncUser { user_id }.run(state).await.unwrap();

        let remaining = sqlx::query_scalar!(
            "SELECT review_id FROM pending_reviews WHERE user_id = $1",
            user_id
        )
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(remaining, vec!["R1".to_string()], "R2 reaped, R1 kept");
    }

    // --- SendReminder tests ---

    async fn insert_user_for_reminder(db: &PgPool, threshold_hours: i32) -> Uuid {
        let state = test_state(db.clone(), test_config());
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (
                user_id, github_login, github_user_id, access_token_enc,
                refresh_token_enc, token_expires_at, email, threshold_hours
            )
            VALUES ($1, 'coreyja', 12345, $2, $3, $4, 'corey@example.com', $5)",
            user_id,
            state.crypto.encrypt("tok", user_id.as_bytes()).unwrap(),
            state.crypto.encrypt("ref", user_id.as_bytes()).unwrap(),
            Utc::now() + Duration::days(30),
            threshold_hours,
        )
        .execute(db)
        .await
        .unwrap();
        user_id
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_reminder_review(
        db: &PgPool,
        user_id: Uuid,
        review_id: &str,
        pr_title: &str,
        last_comment_at: chrono::DateTime<Utc>,
        is_backlog: bool,
        dismissed_at: Option<chrono::DateTime<Utc>>,
        notified_at: Option<chrono::DateTime<Utc>>,
    ) -> Uuid {
        let row = sqlx::query!(
            "INSERT INTO pending_reviews (
                review_id, user_id, pr_url, pr_title, repo_name_with_owner,
                comment_count, last_comment_at, last_seen_at, is_backlog,
                dismissed_at, notified_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id",
            review_id,
            user_id,
            format!("https://github.com/o/r/pull/{}", review_id),
            pr_title,
            "o/r",
            1,
            last_comment_at,
            Utc::now(),
            is_backlog,
            dismissed_at,
            notified_at,
        )
        .fetch_one(db)
        .await
        .unwrap();
        row.id
    }

    #[sqlx::test]
    async fn send_reminder_emails_eligible_reviews(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        // Eligible: stale (5h > 4h), not backlog, not dismissed, not notified
        insert_reminder_review(
            &db,
            user_id,
            "R1",
            "Stale PR",
            Utc::now() - Duration::hours(5),
            false,
            None,
            None,
        )
        .await;
        // Ineligible: not stale (1h < 4h)
        insert_reminder_review(
            &db,
            user_id,
            "R2",
            "Fresh PR",
            Utc::now() - Duration::hours(1),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        {
            let sent = capturing.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].to, "corey@example.com");
            assert!(sent[0].html_body.contains("Stale PR"));
            assert!(!sent[0].html_body.contains("Fresh PR"));
        }

        // notified_at stamped on eligible row only
        let notified: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar!("SELECT notified_at FROM pending_reviews WHERE review_id = 'R1'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(notified.is_some());
        let notified_r2: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar!("SELECT notified_at FROM pending_reviews WHERE review_id = 'R2'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(notified_r2.is_none());
    }

    #[sqlx::test]
    async fn send_reminder_second_tick_does_not_re_email(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 3).await;

        // A review that crossed the threshold between ticks: emailed once by
        // the first run, then the notified_at dedup keeps every subsequent
        // tick quiet.
        insert_reminder_review(
            &db,
            user_id,
            "R1",
            "Crossed between ticks",
            Utc::now() - Duration::hours(4),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state.clone()).await.unwrap();
        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "second tick must not re-email");
        assert!(sent[0].html_body.contains("Crossed between ticks"));
    }

    #[sqlx::test]
    async fn send_reminder_staleness_boundary(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        // Just under threshold (4h - 1s) → NOT eligible (strict >)
        insert_reminder_review(
            &db,
            user_id,
            "R_AT",
            "At threshold",
            Utc::now() - Duration::hours(4) + Duration::seconds(1),
            false,
            None,
            None,
        )
        .await;
        // Just past threshold → eligible
        insert_reminder_review(
            &db,
            user_id,
            "R_PAST",
            "Past threshold",
            Utc::now() - Duration::hours(4) - Duration::seconds(1),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].html_body.contains("Past threshold"));
        assert!(!sent[0].html_body.contains("At threshold"));
    }

    #[sqlx::test]
    async fn send_reminder_per_review_dedup(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        // notified_at < 7 days ago → excluded
        insert_reminder_review(
            &db,
            user_id,
            "R_RECENT",
            "Recently notified",
            Utc::now() - Duration::hours(10),
            false,
            None,
            Some(Utc::now() - Duration::days(3)),
        )
        .await;
        // notified_at > 7 days ago → included
        insert_reminder_review(
            &db,
            user_id,
            "R_OLD",
            "Old notification",
            Utc::now() - Duration::hours(10),
            false,
            None,
            Some(Utc::now() - Duration::days(8)),
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].html_body.contains("Old notification"));
        assert!(!sent[0].html_body.contains("Recently notified"));
    }

    #[sqlx::test]
    async fn send_reminder_excludes_backlog_and_dismissed(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        // Backlog → excluded
        insert_reminder_review(
            &db,
            user_id,
            "R_BACK",
            "Backlog",
            Utc::now() - Duration::hours(10),
            true,
            None,
            None,
        )
        .await;
        // Dismissed → excluded
        insert_reminder_review(
            &db,
            user_id,
            "R_DISM",
            "Dismissed",
            Utc::now() - Duration::hours(10),
            false,
            Some(Utc::now()),
            None,
        )
        .await;
        // Eligible
        insert_reminder_review(
            &db,
            user_id,
            "R_OK",
            "OK",
            Utc::now() - Duration::hours(10),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].html_body.contains("OK"));
        assert!(!sent[0].html_body.contains("Backlog"));
        assert!(!sent[0].html_body.contains("Dismissed"));
    }

    #[sqlx::test]
    async fn send_reminder_caps_at_20(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        for i in 0..25 {
            insert_reminder_review(
                &db,
                user_id,
                &format!("R{}", i),
                &format!("PR {}", i),
                Utc::now() - Duration::hours(5),
                false,
                None,
                None,
            )
            .await;
        }

        SendReminder { user_id }.run(state).await.unwrap();

        {
            let sent = capturing.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            // Count the review rows in the HTML (one meta line per review)
            let row_count = sent[0].html_body.matches("since last comment").count();
            assert_eq!(row_count, 20);
        }

        // All 20 eligible rows stamped
        let notified_count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM pending_reviews WHERE user_id = $1 AND notified_at IS NOT NULL",
            user_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(notified_count, Some(20));
    }

    #[sqlx::test]
    async fn send_reminder_no_eligible_no_email(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;

        // Only fresh review → not eligible
        insert_reminder_review(
            &db,
            user_id,
            "R1",
            "Fresh",
            Utc::now() - Duration::hours(1),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 0);
    }

    #[sqlx::test]
    async fn send_reminder_skips_inactive_user(db: PgPool) {
        let capturing = Arc::new(crate::email::CapturingSender::default());
        let state = crate::state::test_support::test_state_with_mailer(
            db.clone(),
            test_config(),
            capturing.clone(),
        );
        let user_id = insert_user_for_reminder(&db, 4).await;
        sqlx::query!(
            "UPDATE users SET status = 'paused' WHERE user_id = $1",
            user_id
        )
        .execute(&db)
        .await
        .unwrap();

        insert_reminder_review(
            &db,
            user_id,
            "R1",
            "Stale",
            Utc::now() - Duration::hours(10),
            false,
            None,
            None,
        )
        .await;

        SendReminder { user_id }.run(state).await.unwrap();

        let sent = capturing.sent.lock().unwrap();
        assert_eq!(sent.len(), 0);
    }
}
