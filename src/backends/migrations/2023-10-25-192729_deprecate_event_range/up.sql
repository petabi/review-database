ALTER TABLE IF EXISTS column_description
    DROP COLUMN IF EXISTS cluster_id,
    DROP COLUMN IF EXISTS batch_ts,
    ADD COLUMN cluster_id INTEGER default 0,
    ADD COLUMN batch_ts TIMESTAMP default 'EPOCH'::TIMESTAMP;

UPDATE column_description
    SET cluster_id = e.cluster_id, batch_ts = e.time
    FROM event_range AS e
    WHERE column_description.event_range_ids[1] = e.id;

ALTER TABLE IF EXISTS column_description
    ALTER COLUMN cluster_id SET NOT NULL,
    ALTER COLUMN batch_ts SET NOT NULL,
    DROP COLUMN event_range_ids;

DROP TABLE IF EXISTS event_range CASCADE;
