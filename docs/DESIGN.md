# Design

Digest of the spec (2026-07-15, from Corey) plus decisions made during the build.
This is the source of truth for implementation agents.

## Verified facts (spikes, 2026-07-15)

1. GraphQL `search(type: ISSUE, q: "is:pr is:open involves:<login>")` with nested
   `reviews(states: [PENDING], author: "<login>", first: 5) { nodes { id createdAt
   comments(last: 1) { totalCount nodes { createdAt } } } }` returns PENDING reviews to
   their author — verified under both a classic PAT and a GitHub App user token.
   Fixture: `addPullRequestReview` mutation with no `event` param → PENDING review
   (live at coreyja-studio/prn-fixtures#1).
2. `viewer { organizations }` under an App user token returns **zero orgs** (we don't
   request Organization Members: Read). The org coverage-gap feature is **cut** from v1.
   The settings page lists covered installations from `GET /user/installations` instead.
3. Repo-admin installs work without org-owner approval when limited to repos the
   installer administers.

## GitHub App

- Name "Pending Review Notifier", slug `pending-review-notifier`, App ID 4309014,
  Client ID `Iv23lirw3s8aeahbpXt9`. Secret in 1Password ("Pending Review Notifier
  GitHub App", Byte vault). Currently owned by byte-the-bot; transfer to coreyja-studio
  pending (preserves App ID/secret; zero code change).
- Permissions: Repository → Pull requests: Read-only; Account → Email addresses:
  Read-only. Webhook: disabled. Device flow: enabled (testing convenience).
- "Request user authorization (OAuth) during installation" is ON, which **disables the
  Setup URL** — after install, GitHub redirects to the OAuth **callback** with
  `?code=...&installation_id=...&setup_action=install`. There is no `/installed` route;
  `/callback` handles both plain authorization and install-triggered authorization.
- User tokens: ~8h access + ~6mo refresh. **Refresh tokens rotate** — persist the new
  pair atomically or users get locked out. On refresh failure: set user status
  `needs_reauth`, stop syncing, email once.
- We never mint JWTs or installation tokens. User-to-server flow only.

## Core mechanic

- Pending reviews are visible only to their author → every read uses that user's token.
- Discovery: the search query above, paginated at 50/page, ceiling 1000 results (accept).
- Age basis = most recent comment (`comments(last: 1).nodes[0].createdAt`), NOT review
  `createdAt` — someone mid-review shouldn't be nagged. Fall back to review `createdAt`
  if the comment timestamp is missing.
- `comments.totalCount == 0` → abandoned empty review shell, skip entirely.
- Never fetch comment bodies (node-count/rate-limit cost, no detection benefit).
- Pending comments have no permalink; link to `{pr_url}/files`.
- GraphQL rate limit is 5,000 points/hour **per user token** — scales per-user. Back off
  on 403/secondary-limit responses (cja job retry/backoff handles this).

## The anti-flood rule (backlog vs. email)

If a pending review is already past the user's threshold the **first time we see it**,
mark `is_backlog = true`: dashboard only, never emailed. If we watch it cross the
threshold, it's email-eligible. Phrased per-review (not per-first-sync) so a year-later
install on a new org discovering an ancient pile also floods nobody.

- A backlog item that gets a new comment becomes young again (fresh `last_comment_at`)
  and re-enters the email lifecycle when it next goes stale. Correct and desirable.
- Backlog rows are dismissible (`dismissed_at`) so they don't linger forever.

## Data model

```
users
  user_id              uuid pk default gen_random_uuid()
  github_login         text not null
  github_user_id       bigint not null unique   -- stable across renames; key on this
  access_token_enc     bytea not null
  refresh_token_enc    bytea not null
  token_expires_at     timestamptz not null
  email                text not null
  threshold_hours      int not null default 3
  status               text not null default 'active'  -- active | needs_reauth | paused
  reauth_notified_at   timestamptz                     -- "email once" on refresh failure
  created_at           timestamptz not null default now()

installations
  installation_id      bigint pk
  account_login        text not null
  user_id              uuid references users
  repository_selection text not null            -- all | selected
  created_at, last_seen_at timestamptz

pending_reviews
  id                   uuid pk default gen_random_uuid()
  review_id            text not null            -- GraphQL node id
  user_id              uuid not null references users
  pr_url, pr_title, repo_name_with_owner  text not null
  comment_count        int not null
  last_comment_at      timestamptz not null     -- the age basis
  first_seen_at        timestamptz not null default now()
  last_seen_at         timestamptz not null     -- reap rows not seen in a sweep
  is_backlog           boolean not null         -- set on insert per the anti-flood rule
  notified_at          timestamptz              -- last reminder email that included this row
  dismissed_at         timestamptz
  unique(review_id, user_id)
```

Plus cja's own tables (jobs, crons, sessions, dead-letter) vendored from the framework's
migrations, and an app `user_sessions(session_id uuid pk references sessions… , user_id)`
mapping table if needed for dashboard auth (see cja `Session` extractor).

## Jobs & scheduling

- `SyncUser { user_id }` — refresh token if <5 min to expiry → paginate discovery →
  upsert `pending_reviews` (backlog rule applies at insert only) → update
  `last_seen_at` on all seen rows → reap rows not seen this sweep (delete; a submitted
  or discarded review is gone forever). Idempotent; the initial sync is the same job.
- `SyncSweep` — cron every 30 min: enqueue `SyncUser` for every `status = 'active'` user.
- `ReminderSweep` — cron every 15 min: enqueue `SendReminder { user_id }` for every
  `status = 'active'` user. No daily gating: a review is emailed at the first tick after
  it crosses the threshold, so reminders land ~threshold_hours after the user's last
  comment (which also tracks their working hours for free).
- `SendReminder { user_id }` — select rows where `is_backlog = false`, `dismissed_at is
  null`, `now() - last_comment_at > threshold_hours`, and (`notified_at is null` or
  `notified_at < now() - 7 days`) → send one email (cap 20 items) → stamp `notified_at`.
  No qualifying rows → no email; the `notified_at` dedup is what keeps the every-tick
  enqueue quiet after a review has been reminded once.
- cja cron gotchas: the `cron` crate uses **7-field** expressions (sec min hour dom mon
  dow year). A cron/job closure returning `Err` propagates up and **crashes the whole
  app** — wrap job bodies to log-and-continue instead of `?` at the top level.

## Email

MailPace (formerly OhMySMTP) — Corey's choice over Resend. HTTP API:
`POST https://app.mailpace.com/api/v1/send` with `MailPace-Server-Token` header.
Sender abstraction: `MailPace` when `MAILPACE_TOKEN` is set, otherwise a `Stdout` sender
that logs the rendered email (acceptable v1 until a token + verified domain exist).

## Token encryption

XChaCha20-Poly1305 (`chacha20poly1305` crate, `XChaCha20Poly1305`), random 24-byte nonce
prepended to ciphertext, key from `TOKEN_ENC_KEY` env (base64, 32 bytes). Chosen over
`age` (file-format overhead) and AES-GCM (96-bit nonce makes random-nonce-per-refresh a
question; XChaCha20's 192-bit makes it a non-question). We re-encrypt on every token
refresh. No key rotation in v1.

## Auth flow

- `GET /login` → redirect to `https://github.com/login/oauth/authorize` with `client_id`,
  `redirect_uri`, `state` (random, stored in a short-lived cookie). No `scope` param.
- `GET /callback` → verify `state`, exchange code at
  `POST https://github.com/login/oauth/access_token` (Accept: application/json) →
  `access_token`, `refresh_token`, `expires_in`, `refresh_token_expires_in`.
  Fetch `viewer { login databaseId }` + `GET /user/emails` (primary). Upsert user by
  `github_user_id`, encrypt+store tokens, create session, enqueue initial `SyncUser`.
  If the user has no installations (`GET /user/installations`), show the install prompt.
  Handles `setup_action=install` identically (the param is informational).
- `POST /disconnect` → `DELETE /applications/{client_id}/grant` (basic auth client_id:
  client_secret, body `{"access_token": ...}`) to revoke at GitHub, then delete user rows.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | Landing, install/login buttons |
| `GET /login`, `GET /callback` | OAuth |
| `GET /dashboard` | Pending reviews + backlog, dismiss buttons |
| `POST /dismiss/:id` | Dismiss a pending-review row |
| `GET /settings` | Threshold, coverage list, disconnect |
| `POST /settings` | Update settings |
| `POST /disconnect` | Revoke + delete |
| `GET /healthz` | Liveness (version string) |

## CLI mode (end of stack, before wrap-up)

A standalone `prn-check` CLI for people who don't want to trust the hosted service:
runs with a classic PAT (`GITHUB_TOKEN` env) on the user's own cron. Spike #1 verified
a plain PAT sees pending reviews through the same GraphQL query — no GitHub App
involved.

- Same discovery + staleness/backlog logic as the service. **Architectural rule for
  the sync PR: the discovery core (query building, response parsing, staleness
  classification, the backlog rule) must be DB-free** — pure types in/out, no sqlx —
  so the CLI links it without the web/jobs stack.
- Local state file (e.g. `~/.local/state/prn/state.json`) plays the role of the
  `pending_reviews` table: first-seen tracking, the anti-flood backlog rule, and
  notified-at dedupe all work identically.
- Output: human text (cron's MAILTO delivers it) and `--format json`; nonzero exit
  when actionable items exist so people can pipe into their own alerting.
- Distribution: `cargo install` + prebuilt binaries on GitHub Releases.

## Non-goals for v1

Slack/Discord delivery; closed/merged PRs; team dashboards; other people's pending
reviews (impossible); OAuth-App fallback; email body previews; org coverage gaps (cut —
see spike #2).

## Database (Neon)

Prod DB is **Neon**, not Fly Postgres (Corey's call, 2026-07-15): database
`pending_review_notifier`, role `prn`, on the coreyja.com project
(broad-truth-38784432) main branch in the Corey org. **Unpooled** connection string —
sqlx uses prepared statements and Neon's pgbouncer pooler breaks them. Creds in
1Password ("Pending Review Notifier Neon DB", Byte vault). Verified sqlx-cli connects
fine with `sslmode=require&channel_binding=require`. The Fly Postgres cluster
originally provisioned was destroyed before first deploy.

## Deferred / assumptions log

- App owned by byte-the-bot pending org transfer (byte lacks org-owner rights).
- MailPace token not yet provisioned → stdout sender in prod until it lands.
- Search's 1000-result ceiling accepted; users with >1000 open involved PRs get partial
  coverage of the oldest tail.
- Repo-level coverage hints (PR repos seen in search vs installation list) — v1.5 idea.
