-- App schema for Pending Review Notifier (see docs/DESIGN.md "Data model")

CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_login TEXT NOT NULL,
  -- Stable across renames; key on this
  github_user_id BIGINT NOT NULL UNIQUE,
  access_token_enc BYTEA NOT NULL,
  refresh_token_enc BYTEA NOT NULL,
  token_expires_at TIMESTAMPTZ NOT NULL,
  email TEXT NOT NULL,
  -- IANA, browser-detected at signup
  timezone TEXT NOT NULL DEFAULT 'UTC',
  digest_hour INT NOT NULL DEFAULT 9 CHECK (digest_hour BETWEEN 0 AND 23),
  threshold_hours INT NOT NULL DEFAULT 4 CHECK (threshold_hours > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'needs_reauth', 'paused')),
  -- "email once" on refresh failure
  reauth_notified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE installations (
  installation_id BIGINT PRIMARY KEY,
  account_login TEXT NOT NULL,
  user_id UUID REFERENCES users (user_id) ON DELETE CASCADE,
  -- all | selected
  repository_selection TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ
);

CREATE INDEX idx_installations_user_id ON installations (user_id);

CREATE TABLE pending_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- GraphQL node id
  review_id TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  pr_url TEXT NOT NULL,
  pr_title TEXT NOT NULL,
  repo_name_with_owner TEXT NOT NULL,
  comment_count INT NOT NULL,
  -- The age basis
  last_comment_at TIMESTAMPTZ NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Reap rows not seen in a sweep
  last_seen_at TIMESTAMPTZ NOT NULL,
  -- Set on insert per the anti-flood rule
  is_backlog BOOLEAN NOT NULL,
  -- Last digest email that included this row
  notified_at TIMESTAMPTZ,
  dismissed_at TIMESTAMPTZ,
  UNIQUE (review_id, user_id)
);

CREATE INDEX idx_pending_reviews_user_id ON pending_reviews (user_id);

CREATE INDEX idx_pending_reviews_user_id_undismissed ON pending_reviews (user_id)
WHERE
  dismissed_at IS NULL;
