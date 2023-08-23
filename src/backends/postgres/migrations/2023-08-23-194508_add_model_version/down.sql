ALTER TABLE IF EXISTS model
    DROP COLUMN version;

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
