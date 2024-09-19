DROP FUNCTION IF EXISTS 
    attempt_outlier_delete(event_ids BIGINT[], event_sources TEXT[], model INTEGER);
DROP TABLE IF EXISTS outlier;
