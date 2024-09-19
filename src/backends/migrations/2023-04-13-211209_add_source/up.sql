ALTER TABLE IF EXISTS cluster
    ADD COLUMN event_sources TEXT[] DEFAULT '{}'::text[] NOT NULL;
UPDATE cluster SET event_sources = ARRAY_FILL(''::TEXT, ARRAY[coalesce(array_length(event_ids, 1),0)]);
ALTER TABLE IF EXISTS cluster
    ALTER COLUMN event_sources SET NOT NULL,
    DROP CONSTRAINT IF EXISTS event_array_length_check,
    ADD CONSTRAINT event_array_length_check CHECK (array_length(event_ids, 1) = array_length(event_sources, 1));

ALTER TABLE IF EXISTS event_range
    ADD COLUMN event_source TEXT DEFAULT '' NOT NULL,
    DROP CONSTRAINT IF EXISTS event_range_unique_constraint,
    ADD CONSTRAINT event_range_unique_constraint UNIQUE (cluster_id, time, event_source, first_event_id, last_event_id);

ALTER TABLE IF EXISTS outlier
    ADD COLUMN event_sources TEXT[] DEFAULT '{}'::text[] NOT NULL;
UPDATE outlier SET event_sources = ARRAY_FILL(''::TEXT, ARRAY[coalesce(array_length(event_ids, 1),0)]);
ALTER TABLE IF EXISTS outlier
    ALTER COLUMN event_sources SET NOT NULL,
    DROP CONSTRAINT IF EXISTS event_array_length_check,
    ADD CONSTRAINT event_array_length_check CHECK (array_length(event_ids, 1) = array_length(event_sources, 1));

ALTER TABLE IF EXISTS column_description
    ADD COLUMN event_range_ids INTEGER[] DEFAULT '{}'::integer[] NOT NULL;
UPDATE column_description SET event_range_ids = ARRAY[event_range_id];
DROP INDEX IF EXISTS column_description_idx;
CREATE INDEX IF NOT EXISTS column_description_idx ON column_description(event_range_ids, column_index);
ALTER TABLE IF EXISTS column_description
    DROP COLUMN event_range_id,
    ALTER COLUMN event_range_ids SET NOT NULL;

/******************************************************
 * ATTEMPT CLUSTER UPSERT
 *
 * attempt to upsert a cluster
 * return the number of rows updated (0 or 1)
 *
 * The nullable parameters of function should be placed after non-nullable parameters.
 ******************************************************/
DROP FUNCTION IF EXISTS attempt_cluster_upsert;
CREATE FUNCTION attempt_cluster_upsert(
  clusterid VARCHAR,
  detector_id INTEGER,
  event_ids BIGINT[],
  event_sources TEXT[],
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
  _event_sources TEXT[];
  _event_ids_update BIGINT[];
  _event_sources_update TEXT[];
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
    cluster.event_ids, cluster.event_sources, cluster.size, cluster.score
  INTO
    _event_ids, _event_sources, _size, _score
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
    _event_sources := array_cat($4, _event_sources);
    IF array_length(_event_ids, 1) > _max_event_id_num THEN
      LOOP
        SELECT ARRAY_AGG(t.id), ARRAY_AGG(t.src)
        INTO _event_ids_update, _event_sources_update
        FROM (
          SELECT _event_ids[i] AS id, _event_sources[i] AS src
          FROM generate_series(1, array_length(_event_ids, 1)) i
          WHERE _event_ids[i] <> (SELECT MIN(j) FROM unnest(_event_ids) j)
        ) t;

        _event_ids := _event_ids_update;
        _event_sources := _event_sources_update;
        IF (array_length(_event_ids, 1) > _max_event_id_num) IS NOT TRUE THEN
          EXIT;
        END IF;
      END LOOP;
    END IF;
  ELSE
    _event_ids := $3;
    _event_sources := $4;
  END IF;

  INSERT INTO cluster (
    cluster_id,
    detector_id,
    event_ids,
    event_sources,
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
      event_sources = _event_sources,
      last_modification_time = CURRENT_TIMESTAMP(0) at time zone 'UTC',
      score = _score,
      signature = $6,
      size = _size,
      status_id = $8,
      labels = $9;

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
  _event_sources TEXT[];
  _event_ids_update BIGINT[];
  _event_sources_update TEXT[];
BEGIN
  FOR _id, _event_ids IN
    SELECT cluster.id, cluster.event_ids, cluster.event_sources, cluster.model_id
    FROM cluster
    WHERE array_length(cluster.event_ids, 1) > NEW.max_event_id_num
      AND cluster.model_id = OLD.id
  LOOP
    LOOP
      SELECT ARRAY_AGG(t.id), ARRAY_AGG(t.src)
        INTO _event_ids_update, _event_sources_update
        FROM (
          SELECT _event_ids[i] AS id, _event_sources[i] AS src
          FROM generate_series(1, array_length(_event_ids, 1)) i
          WHERE _event_ids[i] <> (SELECT MIN(j) FROM unnest(_event_ids) j)
        ) t;
      _event_ids := _event_ids_update;
      _event_sources := _event_sources_update;
      IF (array_length(_event_ids, 1) > NEW.max_event_id_num) IS NOT TRUE THEN
        EXIT;
      END IF;
    END LOOP;
    UPDATE cluster SET event_ids = _event_ids, event_sources = _event_sources WHERE cluster.id = _id;
  END LOOP;

  FOR _id, _event_ids, _event_sources IN
    SELECT outlier.id, outlier.event_ids, outlier.event_sources
    FROM outlier
    WHERE array_length(outlier.event_ids, 1) > NEW.max_event_id_num
      AND outlier.model_id = OLD.id
  LOOP
    LOOP
      SELECT ARRAY_AGG(t.id), ARRAY_AGG(t.src)
        INTO _event_ids_update, _event_sources_update
        FROM (
          SELECT _event_ids[i] AS id, _event_sources[i] AS src
          FROM generate_series(1, array_length(_event_ids, 1)) i
          WHERE _event_ids[i] <> (SELECT MIN(j) FROM unnest(_event_ids) j)
        ) t;
      _event_ids := _event_ids_update;
      _event_sources := _event_sources_update;
      IF (array_length(_event_ids, 1) > NEW.max_event_id_num) IS NOT TRUE THEN
        EXIT;
      END IF;
    END LOOP;
    UPDATE outlier SET event_ids = _event_ids, event_sources = _event_sources WHERE outlier.id = _id;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

/******************************************************
 * ATTEMPT OUTLIER DELETE
 *
 * attempt to delete outliers with matching event_ids.
 ******************************************************/
DROP FUNCTION IF EXISTS attempt_outlier_delete;
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

/******************************************************
 * ATTEMPT OUTLIER UPSERT
 *
 * attempt to insert or update an outlier
 * return the number of rows updated (0 or 1)
 ******************************************************/
DROP FUNCTION IF EXISTS attempt_outlier_upsert;
CREATE FUNCTION attempt_outlier_upsert(
  is_new_outlier BOOL,
  raw_event BYTEA,
  model_id INTEGER,
  event_ids BIGINT[],
  event_sources TEXT[],
  size BIGINT
)
RETURNS INTEGER AS
$$
DECLARE
   _event_ids BIGINT[];
  _event_sources TEXT[];
  _event_ids_update BIGINT[];
  _event_sources_update TEXT[];
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
      (raw_event, model_id, event_ids, event_sources, size)
      VALUES
      ($2, $3, $4, $5, $6);
  ELSE
    SELECT outlier.id, outlier.event_ids, outlier.event_sources, outlier.size
    INTO _id, _event_ids, _event_sources, _size
    FROM outlier
    WHERE outlier.raw_event = $2
    LIMIT 1;
    IF NOT FOUND THEN
      RETURN 0;
    END IF;

    _size = _size + $6;
    _event_ids = array_cat($4, _event_ids);
    _event_sources = array_cat($5, _event_sources);

    IF array_length(_event_ids, 1) > _max_event_id_num THEN
      LOOP
        SELECT ARRAY_AGG(t.id), ARRAY_AGG(t.src)
        INTO _event_ids_update, _event_sources_update
        FROM (
          SELECT _event_ids[i] AS id, _event_sources[i] AS src
          FROM generate_series(1, array_length(_event_ids, 1)) i
          WHERE _event_ids[i] <> (SELECT MIN(j) FROM unnest(_event_ids) j)
        ) t;
        _event_ids := _event_ids_update;
        _event_sources := _event_sources_update;
        IF (array_length(_event_ids, 1) > _max_event_id_num) IS NOT TRUE THEN
          EXIT;
        END IF;
      END LOOP;
    END IF;

    UPDATE outlier
      SET
        event_ids = _event_ids,
        event_sources = _event_sources,
        size = _size
      WHERE outlier.id = _id;
  END IF;
  RETURN 1;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS event_ids_update_trigger ON model;
CREATE TRIGGER event_ids_update_trigger
  AFTER UPDATE ON model
  FOR EACH ROW
  WHEN (old.max_event_id_num > new.max_event_id_num)
  EXECUTE PROCEDURE attempt_event_ids_update();
