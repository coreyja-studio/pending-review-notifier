-- Maps cja's sessions to app users. A session with no mapping row is a
-- signed-out (anonymous) session; logout deletes the mapping, disconnect
-- deletes the user (cascades here) and the session row itself.
CREATE TABLE user_sessions (
  session_id UUID PRIMARY KEY REFERENCES sessions (session_id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);
