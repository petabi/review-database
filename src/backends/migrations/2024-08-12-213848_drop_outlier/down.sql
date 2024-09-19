CREATE FUNCTION attempt_outlier_delete(
  event_ids BIGINT[],
  event_sources TEXT[],
  model INTEGER
)
RETURNS INTEGER AS
$$
DECLARE
  _ids INTEGER[];
BEGIN
  SELECT array_agg(DISTINCT t.id)
  INTO _ids
  FROM (SELECT outlier.id, unnest(outlier.event_ids) as event_id, unnest(outlier.event_sources) as event_source, model_id FROM outlier WHERE model_id = $3) t
  JOIN (SELECT unnest($1) AS eid, unnest($2) AS src) input
  ON event_id = input.eid AND event_source = input.src;

  DELETE FROM outlier
  WHERE id = ANY(_ids);

  RETURN 1;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS outlier (
  id SERIAL PRIMARY KEY,
  raw_event BYTEA NOT NULL,
  model_id INTEGER NOT NULL,
  event_ids BIGINT[] NOT NULL,
  size BIGINT NOT NULL,
  event_sources text[] NOT NULL
);
