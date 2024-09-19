CREATE TABLE IF NOT EXISTS qualifier (
  id INTEGER PRIMARY KEY,
  description TEXT NOT NULL UNIQUE
);
INSERT INTO qualifier VALUES(1,'benign') ON CONFLICT DO NOTHING;
INSERT INTO qualifier VALUES(2,'unknown') ON CONFLICT DO NOTHING;
INSERT INTO qualifier VALUES(3,'suspicious') ON CONFLICT DO NOTHING;
INSERT INTO qualifier VALUES(4,'mixed') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS status (
  id INTEGER PRIMARY KEY,
  description TEXT NOT NULL UNIQUE
);
INSERT INTO status VALUES(1,'reviewed') ON CONFLICT DO NOTHING;
INSERT INTO status VALUES(2,'pending review') ON CONFLICT DO NOTHING;
INSERT INTO status VALUES(3,'disabled') ON CONFLICT DO NOTHING;

/******************************************************
 * STATUS_ID UPDATE
 *
 * Update status_id to id of `reviewed` in status table
 * Called when qualifier_update_trigger is fired.
 ******************************************************/
CREATE OR REPLACE FUNCTION status_id_update()
RETURNS TRIGGER AS
$$
DECLARE
  new_status_id INTEGER;
BEGIN
  UPDATE cluster
  SET status_id = status.id
  FROM status
  WHERE cluster.id = new.id
    AND status.description = 'reviewed';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

/******************************************************
 * CREATE TRIGGERS 
 *
 * 'CREATE OR REPLACE TRIGGER' is not supported in
 * PostgreSQL 13 or lower.
 ******************************************************/
DROP TRIGGER IF EXISTS qualifier_update_trigger ON cluster;
CREATE TRIGGER qualifier_update_trigger
  AFTER UPDATE ON cluster
  FOR EACH ROW
  WHEN (old.qualifier_id != new.qualifier_id)
  EXECUTE PROCEDURE status_id_update();
