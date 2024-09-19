CREATE TABLE IF NOT EXISTS event_range (
    id SERIAL PRIMARY KEY,
    cluster_id INTEGER NOT NULL,
    time TIMESTAMP NOT NULL,
    first_event_id BIGINT NOT NULL,
    last_event_id BIGINT NOT NULL,
    event_source TEXT NOT NULL,
    UNIQUE (cluster_id, time, event_source, first_event_id, last_event_id)
);

UPDATE event_range AS e
    SET cluster_id = c.cluster_id, time = c.batch_ts, first_event_id = EXTRACT(EPOCH FROM c.batch_ts) * 1000000000 + EXTRACT(MICROSECONDS FROM c.batch_ts) * 1000, last_event_id = first_event_id, event_source = ''
    FROM column_description AS c;

ALTER TABLE IF EXISTS column_description
    ADD COLUMN IF NOT EXISTS event_range_ids INTEGER[] DEFAULT '{}'::integer[] NOT NULL;

UPDATE column_description AS c
    SET event_range_ids = ARRAY[e.id]
    FROM event_range AS e
    WHERE c.cluster_id = e.id AND c.batch_ts = e.time;

ALTER TABLE IF EXISTS column_description
    DROP COLUMN cluster_id,
    DROP COLUMN batch_ts;
