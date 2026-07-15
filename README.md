# Pending Review Notifier

GitHub lets you leave review comments on a PR without submitting the review — they sit
PENDING, visible only to you, forever. This service notices and emails you when a *new*
pending review goes stale, and shows the whole backlog on a dashboard.

Distributed as a GitHub App: install, connect, done.

## Architecture

- Rust on the [cja](https://cja.app) framework (Axum + Postgres-backed jobs/cron/sessions)
- GitHub App **user-to-server** tokens only — pending reviews are visible only to their
  author, so every read is performed as the user
- Discovery: GraphQL `search` (`is:pr is:open involves:<login>`) with nested
  `reviews(states: [PENDING], author: <login>)` — one round trip per 50 PRs
- Anti-flood rule: a review already stale when first seen is **backlog** (dashboard only,
  never emailed); only reviews we *watch* cross the threshold get email
- Deployed on Fly.io; database on Neon
