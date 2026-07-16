//! Pending-review discovery core.
//!
//! **Architectural rule (docs/DESIGN.md "CLI mode"): this module is DB-free.**
//! No sqlx, no [`AppState`](crate::state::AppState) — pure types plus HTTP
//! against a caller-supplied [`reqwest::Client`] and access token. The
//! forthcoming `prn-check` CLI links this module directly, without the web or
//! jobs stack, so nothing here may reach for the database or app state.
//!
//! What lives here: the GraphQL search query, response parsing (including the
//! age-basis and empty-shell rules), the staleness test, and the anti-flood
//! backlog rule. Persistence (the `pending_reviews` table for the service, a
//! JSON state file for the CLI) is the caller's job.

use chrono::{DateTime, Duration, Utc};
use color_eyre::eyre::{Result, WrapErr, eyre};
use serde::Deserialize;

/// Hard ceiling on total results, matching GitHub search's own 1000-result
/// limit (docs/DESIGN.md accepts partial coverage of the oldest tail beyond
/// this). Also a belt-and-suspenders guard against a pagination loop.
const MAX_RESULTS: usize = 1000;

/// The GraphQL query. `$q` is a search string (`is:pr is:open involves:<login>`)
/// and `$author` scopes the nested review lookup to the caller — both passed as
/// variables, never interpolated. `comments(last: 1)` gives us the most-recent
/// comment timestamp (the staleness age basis) and `totalCount` in one shot; we
/// deliberately never fetch comment bodies (node/rate-limit cost, no benefit).
const SEARCH_QUERY: &str = r"
query($q: String!, $author: String!, $after: String) {
  search(type: ISSUE, query: $q, first: 50, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      __typename
      ... on PullRequest {
        url
        title
        repository { nameWithOwner }
        reviews(states: [PENDING], author: $author, first: 5) {
          nodes {
            id
            createdAt
            comments(last: 1) {
              totalCount
              nodes { createdAt }
            }
          }
        }
      }
    }
  }
}";

/// One pending review discovered for a user, reduced to the fields we persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredReview {
    /// GraphQL node id of the review.
    pub review_id: String,
    pub pr_url: String,
    pub pr_title: String,
    pub repo_name_with_owner: String,
    pub comment_count: i32,
    /// Staleness age basis: the most recent comment's timestamp, falling back
    /// to the review's own `createdAt` when the comment timestamp is missing.
    pub last_comment_at: DateTime<Utc>,
}

/// A review is stale once its age basis is older than the user's threshold.
#[must_use]
pub fn is_stale(last_comment_at: DateTime<Utc>, threshold_hours: i32, now: DateTime<Utc>) -> bool {
    now - last_comment_at > Duration::hours(i64::from(threshold_hours))
}

/// The anti-flood backlog rule (docs/DESIGN.md "The anti-flood rule").
///
/// Returns the `is_backlog` flag to persist for a review, given whatever we had
/// stored before (`None` for a brand-new review) and whether it is stale *now*.
///
/// - Brand-new + already stale → **backlog**: we never watched it cross the
///   threshold, so it is dashboard-only and never emailed.
/// - Brand-new + still fresh → not backlog: we will watch it go stale later and
///   that crossing is email-eligible.
/// - Was backlog + now fresh → **clears**: e.g. a new comment revived it; from
///   here we are watching it, so its next staleness crossing may email.
/// - Was backlog + still stale → stays backlog.
/// - Was non-backlog → stays non-backlog (backlog only ever goes true→false).
///
/// Both callers resolve the flag *here* and then persist it verbatim: the
/// service reads the prior flag, calls this, and writes `is_backlog =
/// EXCLUDED.is_backlog`; the CLI does the same against its JSON state file. The
/// rule has one home so the two can never drift.
#[must_use]
pub fn resolve_backlog(previous: Option<bool>, stale_now: bool) -> bool {
    match previous {
        None => stale_now,
        Some(prev) => prev && stale_now,
    }
}

/// Discover every pending review the given user token can see, paginating up to
/// the [`MAX_RESULTS`] ceiling. DB-free: takes primitives so the CLI reuses it.
pub async fn discover_pending_reviews(
    http: &reqwest::Client,
    api_base: &str,
    access_token: &str,
    login: &str,
) -> Result<Vec<DiscoveredReview>> {
    // `sort:created-asc` makes pagination deterministic. It is a no-op for the
    // common case (<1000 involved PRs → same set every sweep) but matters past
    // the MAX_RESULTS ceiling: without a stable sort, search's default
    // relevance order would surface a different arbitrary 1000 each sweep, and
    // the reap would churn rows in and out — resetting first_seen_at and the
    // backlog flag on genuinely-tracked reviews. Oldest-first also keeps the
    // reviews most likely to be stale inside the covered window.
    let search_q = format!("is:pr is:open involves:{login} sort:created-asc");
    let mut reviews = Vec::new();
    let mut after: Option<String> = None;

    loop {
        let variables = serde_json::json!({
            "q": search_q,
            "author": login,
            "after": after,
        });
        let page = search_page(http, api_base, access_token, &variables)
            .await
            .wrap_err("pending-review search request failed")?;

        for node in page.search.nodes {
            extract_reviews(&node, &mut reviews);
        }

        if reviews.len() >= MAX_RESULTS || !page.search.page_info.has_next_page {
            break;
        }
        match page.search.page_info.end_cursor {
            Some(cursor) => after = Some(cursor),
            // hasNextPage was true but no cursor — bail rather than loop forever.
            None => break,
        }
    }

    reviews.truncate(MAX_RESULTS);
    Ok(reviews)
}

/// Pull the pending reviews out of one search node, applying the age-basis and
/// empty-shell rules. Non-PR nodes (search can return issues) contribute
/// nothing. Split out so it is unit-testable without a live GraphQL endpoint.
fn extract_reviews(node: &SearchNode, out: &mut Vec<DiscoveredReview>) {
    for review in &node.reviews.nodes {
        // An empty review shell (no comments) means someone opened a review and
        // wrote nothing — not a pending comment worth nagging about. Skip it.
        if review.comments.total_count == 0 {
            continue;
        }

        let last_comment_at = review
            .comments
            .nodes
            .first()
            .map_or(review.created_at, |c| c.created_at);

        out.push(DiscoveredReview {
            review_id: review.id.clone(),
            pr_url: node.url.clone(),
            pr_title: node.title.clone(),
            repo_name_with_owner: node.repository.name_with_owner.clone(),
            comment_count: review.comments.total_count,
            last_comment_at,
        });
    }
}

async fn search_page(
    http: &reqwest::Client,
    api_base: &str,
    access_token: &str,
    variables: &serde_json::Value,
) -> Result<SearchData> {
    let response = http
        .post(format!("{api_base}/graphql"))
        .bearer_auth(access_token)
        .json(&serde_json::json!({ "query": SEARCH_QUERY, "variables": variables }))
        .send()
        .await?
        .error_for_status()?;

    let body: GraphQlResponse = response.json().await?;

    // GraphQL reports errors in a 200 body. Surface them (including secondary
    // rate limits) so the job layer retries/backs off rather than treating a
    // failed page as "no pending reviews" and reaping the user's real rows.
    if let Some(errors) = body.errors
        && !errors.is_empty()
    {
        let joined = errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(eyre!("GraphQL search returned errors: {joined}"));
    }

    body.data
        .ok_or_else(|| eyre!("GraphQL search returned no data"))
}

#[derive(Deserialize)]
struct GraphQlResponse {
    data: Option<SearchData>,
    errors: Option<Vec<GraphQlError>>,
}

#[derive(Deserialize)]
struct GraphQlError {
    message: String,
}

#[derive(Deserialize)]
struct SearchData {
    search: SearchConnection,
}

#[derive(Deserialize)]
struct SearchConnection {
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
    nodes: Vec<SearchNode>,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

/// A search result node. Non-PR results (issues) deserialize with the default
/// empty fields via `#[serde(default)]`, contributing no reviews.
#[derive(Deserialize, Default)]
#[serde(default)]
struct SearchNode {
    url: String,
    title: String,
    repository: Repository,
    reviews: ReviewConnection,
}

#[derive(Deserialize, Default)]
struct Repository {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
}

#[derive(Deserialize, Default)]
struct ReviewConnection {
    nodes: Vec<ReviewNode>,
}

#[derive(Deserialize)]
struct ReviewNode {
    id: String,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    comments: CommentConnection,
}

#[derive(Deserialize)]
struct CommentConnection {
    #[serde(rename = "totalCount")]
    total_count: i32,
    nodes: Vec<CommentNode>,
}

#[derive(Deserialize)]
struct CommentNode {
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn parse_node(json: serde_json::Value) -> Vec<DiscoveredReview> {
        let node: SearchNode = serde_json::from_value(json).unwrap();
        let mut out = Vec::new();
        extract_reviews(&node, &mut out);
        out
    }

    #[test]
    fn is_stale_compares_age_basis_to_threshold() {
        let now = ts("2026-07-15T12:00:00Z");
        // 5h old, 4h threshold → stale.
        assert!(is_stale(ts("2026-07-15T07:00:00Z"), 4, now));
        // 3h old, 4h threshold → fresh.
        assert!(!is_stale(ts("2026-07-15T09:00:00Z"), 4, now));
        // Exactly at the threshold is not yet stale (strictly greater-than).
        assert!(!is_stale(ts("2026-07-15T08:00:00Z"), 4, now));
    }

    #[test]
    fn resolve_backlog_follows_the_anti_flood_rule() {
        // Brand-new: backlog iff already stale on first sight.
        assert!(resolve_backlog(None, true));
        assert!(!resolve_backlog(None, false));
        // A backlog row seen fresh (e.g. new comment) clears; still stale stays.
        assert!(!resolve_backlog(Some(true), false));
        assert!(resolve_backlog(Some(true), true));
        // A non-backlog row never becomes backlog.
        assert!(!resolve_backlog(Some(false), true));
        assert!(!resolve_backlog(Some(false), false));
    }

    #[test]
    fn age_basis_is_the_latest_comment_not_the_review() {
        let reviews = parse_node(serde_json::json!({
            "__typename": "PullRequest",
            "url": "https://github.com/o/r/pull/1",
            "title": "Fix the thing",
            "repository": { "nameWithOwner": "o/r" },
            "reviews": { "nodes": [{
                "id": "REVIEW_1",
                "createdAt": "2026-07-10T00:00:00Z",
                "comments": {
                    "totalCount": 3,
                    "nodes": [{ "createdAt": "2026-07-14T09:30:00Z" }]
                }
            }]}
        }));
        assert_eq!(reviews.len(), 1);
        let r = &reviews[0];
        assert_eq!(r.review_id, "REVIEW_1");
        assert_eq!(r.pr_url, "https://github.com/o/r/pull/1");
        assert_eq!(r.pr_title, "Fix the thing");
        assert_eq!(r.repo_name_with_owner, "o/r");
        assert_eq!(r.comment_count, 3);
        // Age basis is the comment time, NOT the review createdAt.
        assert_eq!(r.last_comment_at, ts("2026-07-14T09:30:00Z"));
    }

    #[test]
    fn age_basis_falls_back_to_review_created_at_when_no_comment_node() {
        // totalCount > 0 but the comment node is absent (e.g. clipped) → fall
        // back to the review's own createdAt rather than dropping the review.
        let reviews = parse_node(serde_json::json!({
            "__typename": "PullRequest",
            "url": "https://github.com/o/r/pull/2",
            "title": "Another",
            "repository": { "nameWithOwner": "o/r" },
            "reviews": { "nodes": [{
                "id": "REVIEW_2",
                "createdAt": "2026-07-11T08:00:00Z",
                "comments": { "totalCount": 1, "nodes": [] }
            }]}
        }));
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].last_comment_at, ts("2026-07-11T08:00:00Z"));
    }

    #[test]
    fn issue_nodes_contribute_no_reviews() {
        // `search(type: ISSUE)` can return Issues alongside PRs. A non-PR node
        // omits the inline-fragment fields entirely; `#[serde(default)]` gives
        // it empty defaults (no reviews) rather than failing the page.
        let reviews = parse_node(serde_json::json!({ "__typename": "Issue" }));
        assert!(reviews.is_empty());
    }

    #[test]
    fn empty_review_shells_are_skipped() {
        let reviews = parse_node(serde_json::json!({
            "__typename": "PullRequest",
            "url": "https://github.com/o/r/pull/3",
            "title": "Empty shell",
            "repository": { "nameWithOwner": "o/r" },
            "reviews": { "nodes": [{
                "id": "REVIEW_3",
                "createdAt": "2026-07-11T08:00:00Z",
                "comments": { "totalCount": 0, "nodes": [] }
            }]}
        }));
        assert!(reviews.is_empty());
    }
}
