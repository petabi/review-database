CREATE TABLE IF NOT EXISTS cluster (
  id SERIAL PRIMARY KEY,
  category_id INTEGER NOT NULL DEFAULT 1,
  cluster_id TEXT NOT NULL,
  detector_id INTEGER NOT NULL,
  event_ids BIGINT[] NOT NULL,
  labels TEXT[],
  last_modification_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  model_id INTEGER NOT NULL,
  qualifier_id INTEGER NOT NULL DEFAULT 2,
  score FLOAT8,
  signature TEXT NOT NULL,
  size BIGINT NOT NULL,
  status_id INTEGER NOT NULL DEFAULT 3,
  UNIQUE (cluster_id, model_id)
);

CREATE TABLE IF NOT EXISTS model (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  max_event_id_num INTEGER NOT NULL,
  data_source_id INTEGER NOT NULL,
  classifier BYTEA,
  classification_id BIGINT,
  version INTEGER NOT NULL,
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS time_series (
    id SERIAL PRIMARY KEY,
    cluster_id INTEGER NOT NULL,
    time TIMESTAMP NOT NULL,
    count_index INTEGER,
    value TIMESTAMP NOT NULL,
    count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS time_series_cluster_id ON time_series (cluster_id);

CREATE OR REPLACE FUNCTION attempt_cluster_upsert(
  clusterid INTEGER,
  detector_id INTEGER,
  event_ids BIGINT[],
  sensors TEXT[],
  model_id_arg INTEGER,
  signature VARCHAR,
  size BIGINT,
  status_id INTEGER,
  labels VARCHAR[] DEFAULT NULL,
  score FLOAT8 DEFAULT NULL
)
RETURNS INTEGER AS
$$
DECLARE
  _max_event_id_num INTEGER;
  _event_ids BIGINT[];
  _sensors TEXT[];
  _event_ids_update BIGINT[];
  _sensors_update TEXT[];
  _size BIGINT;
  _score FLOAT8;
BEGIN

  SELECT max_event_id_num
  INTO _max_event_id_num
  FROM model
  WHERE id = $5
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  SELECT
    cluster.event_ids, cluster.sensors, cluster.size, cluster.score
  INTO
    _event_ids, _sensors, _size, _score
  FROM cluster
  WHERE cluster.cluster_id = $1
    and cluster.model_id = $5
  LIMIT 1;

  IF _size IS NULL THEN
    _size := $7;
  ELSE
    _size := _size + $7;
  END IF;

  IF $10 IS NOT NULL THEN
    _score := $10;
  END IF;

  IF _event_ids IS NOT NULL THEN
    _event_ids := array_cat($3, _event_ids);
    _sensors := array_cat($4, _sensors);
    IF array_length(_event_ids, 1) > _max_event_id_num THEN
      LOOP
        SELECT ARRAY_AGG(t.id), ARRAY_AGG(t.src)
        INTO _event_ids_update, _sensors_update
        FROM (
          SELECT _event_ids[i] AS id, _sensors[i] AS src
          FROM generate_series(1, array_length(_event_ids, 1)) i
          WHERE _event_ids[i] <> (SELECT MIN(j) FROM unnest(_event_ids) j)
        ) t;

        _event_ids := _event_ids_update;
        _sensors := _sensors_update;
        IF (array_length(_event_ids, 1) > _max_event_id_num) IS NOT TRUE THEN
          EXIT;
        END IF;
      END LOOP;
    END IF;
  ELSE
    _event_ids := $3;
    _sensors := $4;
  END IF;

  INSERT INTO cluster (
    cluster_id,
    detector_id,
    event_ids,
    sensors,
    last_modification_time,
    model_id,
    signature,
    size,
    status_id,
    labels,
    score
    )
  VALUES
    ($1, $2, $3, $4, NULL, $5, $6, _size, $8, $9, $10)
  ON CONFLICT (cluster_id, model_id)
  DO UPDATE
    SET
      event_ids = _event_ids,
      sensors = _sensors,
      last_modification_time = CURRENT_TIMESTAMP(0) at time zone 'UTC',
      score = _score,
      signature = $6,
      size = _size,
      status_id = $8,
      labels = $9;

  RETURN 1;
END;
$$ LANGUAGE plpgsql;
