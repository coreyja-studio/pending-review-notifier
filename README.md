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

## prn-check: the standalone CLI

Don't want to hand a hosted service a token? `prn-check` runs the exact same
detection logic (it links the service's discovery core directly — same GraphQL
search, same staleness test, same anti-flood backlog rule, same 7-day re-alert
dedup) with no server, no OAuth, and no database. State lives in a local JSON
file; auth is a Personal Access Token that never leaves your machine.

### Install

```console
$ cargo install --git https://github.com/coreyja-studio/pending-review-notifier --bin prn-check
# or from a checkout:
$ cargo install --path . --bin prn-check
```

### Token

Create a **classic** Personal Access Token at <https://github.com/settings/tokens>:

- `repo` scope to cover private repositories
- `public_repo` is enough if everything you review is public

Export it as `GITHUB_TOKEN`.

### Usage

```console
$ GITHUB_TOKEN=ghp_... prn-check
Newly actionable pending reviews (1):
  coreyja-studio/some-repo - Fix the thing
    https://github.com/coreyja-studio/some-repo/pull/12/files (3 comments, last activity 26h ago)

Backlog (2; already stale when first seen, never alerts):
  ...
```

- `--threshold-hours <N>` — staleness threshold (default 4, same as the service)
- `--state-file <PATH>` — state location (default `$XDG_STATE_HOME/prn-check/state.json`,
  falling back to `~/.local/state/prn-check/state.json`)
- `--login <LOGIN>` — GitHub login to check (default: whoever the token belongs to)
- `--json` — machine-readable output
- `--quiet` — print only newly actionable reviews (nothing on a quiet run)

Exit codes: `0` nothing newly actionable, `1` newly actionable reviews exist,
`2` error. A review that alerted won't alert again for 7 days, and reviews that
were already stale the first time `prn-check` ever saw them are backlog: shown,
but never cause exit 1.

### Cron

`--quiet` prints nothing unless something newly crossed the threshold, so with
cron's `MAILTO` you get mail exactly when there's something to act on:

```crontab
MAILTO=you@example.com
*/30 * * * * GITHUB_TOKEN=$(cat ~/.config/prn-check/token) prn-check --quiet
```

Or drive your own alerting off the exit code:

```crontab
*/30 * * * * GITHUB_TOKEN=$(cat ~/.config/prn-check/token) prn-check --quiet || notify-send "Pending reviews need attention"
```
