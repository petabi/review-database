ALTER TABLE IF EXISTS column_description
    ADD COLUMN IF NOT EXISTS event_range_ids INTEGER[] DEFAULT '{}'::integer[] NOT NULL;

UPDATE column_description AS c
    SET event_range_ids = ARRAY[e.id]
    FROM event_range AS e
    WHERE c.cluster_id = e.id AND c.batch_ts = e.time;

ALTER TABLE IF EXISTS column_description
    DROP COLUMN cluster_id,
    DROP COLUMN batch_ts;
