ALTER TABLE IF EXISTS model
    ADD COLUMN version INTEGER default 0,
    ALTER COLUMN version SET NOT NULL;


DROP FUNCTION IF EXISTS attempt_outlier_upsert;
