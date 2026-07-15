-- Maps cja's sessions to app users. A session with no mapping row is a
-- signed-out (anonymous) session; logout deletes the mapping, disconnect
-- deletes the user (cascades here) and the session row itself.
CREATE TABLE user_sessions (
  session_id UUID PRIMARY KEY REFERENCES sessions (session_id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  -- Per-session CSRF token (random 32 bytes), rendered into state-changing
  -- forms and validated (constant-time) on POST.
  csrf_token BYTEA NOT NULL,
  -- Sign-in time; sessions older than the max age are rejected and reaped.
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);
