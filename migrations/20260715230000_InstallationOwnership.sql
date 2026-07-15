-- GET /user/installations returns the installations a user can *see*, which
-- overlap between members of the same org. A direct users FK on installations
-- let each login steal the row from the previous member; installations are
-- shared entities, so ownership moves to a join table.
-- (Nothing is deployed with data; this only restructures empty tables.)
ALTER TABLE installations
DROP COLUMN user_id;

CREATE TABLE user_installations (
  user_id UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations (installation_id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, installation_id)
);

CREATE INDEX idx_user_installations_installation_id ON user_installations (installation_id);
