DROP TABLE IF EXISTS qualifier;
DROP TABLE IF EXISTS status;

DROP TRIGGER IF EXISTS qualifier_update_trigger ON cluster;
DROP FUNCTION IF EXISTS status_id_update;
