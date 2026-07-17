-- Reminder pausing + List-Unsubscribe.
--
-- reminders_paused: a user-facing switch, separate from `status` (which is
-- operational: active/needs_reauth/paused-by-us). Sync keeps running while
-- reminders are paused so the dashboard stays truthful.
--
-- unsubscribe_token: the capability secret behind /unsubscribe/{token} — a
-- per-user, unguessable UUID that authenticates the RFC 8058 one-click POST
-- without a session. gen_random_uuid() is built into PG13+ (Neon and the
-- local test DB both qualify).
ALTER TABLE users
ADD COLUMN reminders_paused BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN unsubscribe_token UUID NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX idx_users_unsubscribe_token ON users (unsubscribe_token);
