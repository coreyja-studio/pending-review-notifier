use chrono::Utc;
use cja::jobs::Job;
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

cja::impl_job_registry!(AppState, SyncUser);

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use sqlx::PgPool;
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
}
