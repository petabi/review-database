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
  FOR _id, _event_ids, _event_sources IN
    SELECT cluster.id, cluster.event_ids, cluster.event_sources
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
