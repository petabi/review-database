ALTER TABLE IF EXISTS cluster
    DROP CONSTRAINT IF EXISTS event_array_length_check,
    DROP COLUMN IF EXISTS event_sources;

ALTER TABLE IF EXISTS event_range
    DROP CONSTRAINT IF EXISTS event_range_unique_constraint,
    ADD CONSTRAINT event_range_unique_constraint UNIQUE (cluster_id, time, first_event_id, last_event_id),
    DROP COLUMN IF EXISTS event_source;

ALTER TABLE IF EXISTS outlier
    DROP CONSTRAINT IF EXISTS event_array_length_check,
    DROP COLUMN IF EXISTS event_sources;

ALTER TABLE IF EXISTS column_description
    ADD COLUMN event_range_id INTEGER;
UPDATE column_description SET event_range_id = event_range_ids[1];
ALTER TABLE IF EXISTS column_description
    DROP COLUMN event_range_ids,
    ALTER COLUMN event_range_id SET NOT NULL;
   
DROP TRIGGER IF EXISTS event_ids_update_trigger ON model;
DROP FUNCTION IF EXISTS attempt_cluster_upsert;
DROP FUNCTION IF EXISTS attempt_event_ids_update;
DROP FUNCTION IF EXISTS attempt_outlier_delete;
DROP FUNCTION IF EXISTS attempt_outlier_upsert;
