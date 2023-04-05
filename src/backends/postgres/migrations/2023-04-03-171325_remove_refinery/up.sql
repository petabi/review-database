DROP TABLE IF EXISTS refinery_schema_history;

CREATE TABLE IF NOT EXISTS category (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
INSERT INTO category (name) VALUES('Non-Specified Alert') ON CONFLICT DO NOTHING;
INSERT INTO category (name) VALUES('Irrelevant Alert') ON CONFLICT DO NOTHING;

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

CREATE TABLE IF NOT EXISTS event_range (
  id SERIAL PRIMARY KEY,
  cluster_id INTEGER NOT NULL,
  time TIMESTAMP NOT NULL,
  first_event_id BIGINT NOT NULL,
  last_event_id BIGINT NOT NULL,
  UNIQUE(cluster_id, time, first_event_id, last_event_id)
);

CREATE TABLE IF NOT EXISTS model (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  max_event_id_num INTEGER NOT NULL,
  data_source_id INTEGER NOT NULL,
  classifier BYTEA NOT NULL,
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS outlier (
  id SERIAL PRIMARY KEY,
  raw_event BYTEA NOT NULL,
  model_id INTEGER NOT NULL,
  event_ids BIGINT[] NOT NULL,
  size BIGINT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS column_description (
  id SERIAL PRIMARY KEY,
  event_range_id INTEGER NOT NULL,
  column_index INTEGER NOT NULL,
  type_id INTEGER NOT NULL,
  count BIGINT NOT NULL,
  unique_count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS column_description_idx ON column_description(event_range_id, column_index);

CREATE TABLE IF NOT EXISTS csv_column_extra (
    id SERIAL PRIMARY KEY,
    model_id INTEGER NOT NULL,
    column_alias TEXT[],
    column_display BOOL[],
    column_top_n BOOL[],
    column_1 BOOL[],
    column_n BOOL[],
    UNIQUE(model_id)
);

CREATE TABLE IF NOT EXISTS csv_column_list (
    id SERIAL PRIMARY KEY,
    model_id INTEGER NOT NULL,
    column_indicator TEXT[],
    column_whitelist TEXT[],
    UNIQUE(model_id)
);

CREATE TABLE IF NOT EXISTS csv_indicator (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    list TEXT NOT NULL,
    last_modification_time TIMESTAMP,
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS csv_whitelist (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    list TEXT NOT NULL,
    last_modification_time TIMESTAMP,
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS description_binary (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS description_datetime (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS description_enum (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS description_float (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  min DOUBLE PRECISION,
  max DOUBLE PRECISION,
  mean DOUBLE PRECISION,
  s_deviation DOUBLE PRECISION,
  mode_smallest DOUBLE PRECISION NOT NULL,
  mode_largest DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS description_int (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  min BIGINT,
  max BIGINT,
  mean DOUBLE PRECISION,
  s_deviation DOUBLE PRECISION,
  mode BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS description_ipaddr (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS description_text (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS top_n_binary (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value BYTEA NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_binary_idx_desc_id ON top_n_binary(description_id);

CREATE TABLE IF NOT EXISTS top_n_datetime (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TIMESTAMP NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_datetime_idx_desc_id ON top_n_datetime(description_id);

CREATE TABLE IF NOT EXISTS top_n_enum (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_enum_idx_desc_id ON top_n_enum(description_id);

CREATE TABLE IF NOT EXISTS top_n_float (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value_smallest DOUBLE PRECISION NOT NULL,
  value_largest DOUBLE PRECISION NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_float_idx_desc_id ON top_n_float(description_id);

CREATE TABLE IF NOT EXISTS top_n_int (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value BIGINT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_int_idx_desc_id ON top_n_int(description_id);

CREATE TABLE IF NOT EXISTS top_n_ipaddr (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_ipaddr_idx_desc_id ON top_n_ipaddr(description_id);

CREATE TABLE IF NOT EXISTS top_n_text (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_text_idx_desc_id ON top_n_text(description_id);

/******************************************************
 * ATTEMPT CLUSTER UPSERT
 *
 * attempt to upsert a cluster
 * return the number of rows updated (0 or 1)
 *
 * The nullable parameters of function should be placed after non-nullable parameters.
 ******************************************************/
CREATE OR REPLACE FUNCTION attempt_cluster_upsert(
  clusterid VARCHAR,
  detector_id INTEGER,
  event_ids BIGINT[],
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
  _event_id BIGINT;
  _event_ids BIGINT[];
  _size BIGINT;
  _score FLOAT8;
BEGIN

  SELECT max_event_id_num
  INTO _max_event_id_num
  FROM model
  WHERE id = $4
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  SELECT
    cluster.event_ids, cluster.size, cluster.score
  INTO
    _event_ids, _size, _score
  FROM cluster
  WHERE cluster.cluster_id = $1
    and cluster.model_id = $4
  LIMIT 1;

  IF _size IS NULL THEN
    _size := $6;
  ELSE
    _size := _size + $6;
  END IF;

  IF $9 IS NOT NULL THEN
    _score := $9;
  END IF;

  IF _event_ids IS NOT NULL THEN
    _event_ids := array_cat($3, _event_ids);
    IF array_length(_event_ids, 1) > _max_event_id_num THEN
      LOOP
        EXECUTE 'SELECT MIN(i) FROM UNNEST($1) i' INTO _event_id USING _event_ids;
        _event_ids := array_remove(_event_ids, _event_id);
        IF (array_length(_event_ids, 1) > _max_event_id_num) IS NOT TRUE THEN
          EXIT;
        END IF;
      END LOOP;
    END IF;
  ELSE
    _event_ids := $3;
  END IF;

  INSERT INTO cluster (
    cluster_id,
    detector_id,
    event_ids,
    last_modification_time,
    model_id,
    signature,
    size,
    status_id,
    labels,
    score
    )
  VALUES
    ($1, $2, $3, NULL, $4, $5, _size, $7, $8, $9)
  ON CONFLICT (cluster_id, model_id)
  DO UPDATE
    SET
      event_ids = _event_ids,
      last_modification_time = CURRENT_TIMESTAMP(0) at time zone 'UTC',
      score = _score,
      signature = $5,
      size = _size,
      status_id = $7,
      labels = $8;

  RETURN 1;
END;
$$ LANGUAGE plpgsql;

/******************************************************
 * ATTEMPT_EVENT_IDS_UPDATE
 *
 * Remove unnecessary event_ids from cluster and outlier.
 * Called when event_ids_update_trigger is fired.
 ******************************************************/
CREATE OR REPLACE FUNCTION attempt_event_ids_update()
RETURNS TRIGGER AS
$$
DECLARE
  _id INTEGER;
  _event_ids BIGINT[];
  _event_id BIGINT;
BEGIN
  FOR _id, _event_ids IN
    SELECT cluster.id, cluster.event_ids, cluster.model_id
    FROM cluster
    WHERE array_length(cluster.event_ids, 1) > NEW.max_event_id_num
      AND cluster.model_id = OLD.id
  LOOP
    LOOP
      EXECUTE 'SELECT MIN(i) FROM UNNEST($1) i' INTO _event_id USING _event_ids;
      _event_ids := array_remove(_event_ids, _event_id);
      IF (array_length(_event_ids, 1) > NEW.max_event_id_num) IS NOT TRUE THEN
        EXIT;
      END IF;
    END LOOP;
    UPDATE cluster SET event_ids = _event_ids WHERE cluster.id = _id;
  END LOOP;

  FOR _id, _event_ids IN
    SELECT outlier.id, outlier.event_ids
    FROM outlier
    WHERE array_length(outlier.event_ids, 1) > NEW.max_event_id_num
      AND outlier.model_id = OLD.id
  LOOP
    LOOP
      EXECUTE 'SELECT MIN(i) FROM UNNEST($1) i' INTO _event_id USING _event_ids;
      _event_ids := array_remove(_event_ids, _event_id);
      IF (array_length(_event_ids, 1) > NEW.max_event_id_num) IS NOT TRUE THEN
        EXIT;
      END IF;
    END LOOP;
    UPDATE outlier SET event_ids = _event_ids WHERE outlier.id = _id;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

/******************************************************
 * ATTEMPT OUTLIER DELETE
 *
 * attempt to delete outliers with matching event_ids.
 ******************************************************/
CREATE OR REPLACE FUNCTION attempt_outlier_delete(
  event_ids BIGINT[],
  model INTEGER
)
RETURNS INTEGER AS
$$
DECLARE
  _ids INTEGER[];
BEGIN
  SELECT array_agg(DISTINCT id)
  INTO _ids
  FROM (SELECT outlier.id, unnest(outlier.event_ids) as event_id, model_id FROM outlier) t
  WHERE t.event_id = ANY($1)
    AND t.model_id = $2;

  DELETE FROM outlier
  WHERE id = ANY(_ids);

  RETURN 1;
END;
$$ LANGUAGE plpgsql;

/******************************************************
 * ATTEMPT OUTLIER UPSERT
 *
 * attempt to insert or update an outlier
 * return the number of rows updated (0 or 1)
 ******************************************************/
CREATE OR REPLACE FUNCTION attempt_outlier_upsert(
  is_new_outlier BOOL,
  raw_event BYTEA,
  model_id INTEGER,
  event_ids BIGINT[],
  size BIGINT
)
RETURNS INTEGER AS
$$
DECLARE
  _event_id BIGINT;
  _event_ids BIGINT[];
  _id INTEGER;
  _max_event_id_num INTEGER;
  _size BIGINT;
BEGIN
  SELECT max_event_id_num
  INTO _max_event_id_num
  FROM model
  WHERE id = $3
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF is_new_outlier IS TRUE THEN
    INSERT INTO outlier
      (raw_event, model_id, event_ids, size)
      VALUES
      ($2, $3, $4, $5);
  ELSE
    SELECT outlier.id, outlier.event_ids, outlier.size
    INTO _id, _event_ids, _size
    FROM outlier
    WHERE outlier.raw_event = $2
    LIMIT 1;
    IF NOT FOUND THEN
      RETURN 0;
    END IF;

    _size = _size + $5;
    _event_ids = array_cat($4, _event_ids);

    IF array_length(_event_ids, 1) > _max_event_id_num THEN
      LOOP
        EXECUTE 'SELECT MIN(i) FROM UNNEST($1) i' INTO _event_id USING _event_ids;
        _event_ids := array_remove(_event_ids, _event_id);
        IF (array_length(_event_ids, 1) > _max_event_id_num) IS NOT TRUE THEN
          EXIT;
        END IF;
      END LOOP;
    END IF;

    UPDATE outlier
      SET
        event_ids = _event_ids,
        size = _size
      WHERE outlier.id = _id;
  END IF;
  RETURN 1;
END;
$$ LANGUAGE plpgsql;

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

DROP TRIGGER IF EXISTS event_ids_update_trigger ON model;
CREATE TRIGGER event_ids_update_trigger
  AFTER UPDATE ON model
  FOR EACH ROW
  WHEN (old.max_event_id_num > new.max_event_id_num)
  EXECUTE PROCEDURE attempt_event_ids_update();
