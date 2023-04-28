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
DROP INDEX IF EXISTS column_description_idx;
CREATE INDEX IF NOT EXISTS column_description_idx ON column_description(event_range_id, column_index);
ALTER TABLE IF EXISTS column_description
    DROP COLUMN event_range_ids,
    ALTER COLUMN event_range_id SET NOT NULL;

DROP TRIGGER IF EXISTS event_ids_update_trigger ON model;

DROP FUNCTION IF EXISTS attempt_cluster_upsert;
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

DROP FUNCTION IF EXISTS attempt_event_ids_update;
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

DROP FUNCTION IF EXISTS attempt_outlier_delete;
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

DROP FUNCTION IF EXISTS attempt_outlier_upsert;
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

CREATE TRIGGER event_ids_update_trigger
  AFTER UPDATE ON model
  FOR EACH ROW
  WHEN (old.max_event_id_num > new.max_event_id_num)
  EXECUTE PROCEDURE attempt_event_ids_update();

