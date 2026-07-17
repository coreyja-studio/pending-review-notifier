-- Reminder model: the 15-minute sweep emails as soon as a review newly crosses
-- the staleness threshold — no daily scheduling, so the digest columns go away.
ALTER TABLE users
DROP COLUMN digest_hour,
DROP COLUMN last_digest_at,
DROP COLUMN timezone;

-- The reminder default is 3 hours ("~3 hours after your last comment"). The
-- only real user asked for 3, so anyone still on the old default of 4 is moved
-- rather than left behind; a deliberately chosen non-4 threshold is untouched.
ALTER TABLE users
ALTER COLUMN threshold_hours
SET DEFAULT 3;

UPDATE users
SET
  threshold_hours = 3
WHERE
  threshold_hours = 4;
