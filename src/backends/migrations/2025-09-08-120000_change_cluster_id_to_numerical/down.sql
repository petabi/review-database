-- Revert cluster_id from BIGINT back to TEXT in cluster table
-- This downmigration converts numerical cluster_ids back to string format

-- Create a temporary function to generate string cluster_ids from numerical ids
CREATE OR REPLACE FUNCTION generate_cluster_string(cluster_id_num BIGINT) RETURNS TEXT AS $$
BEGIN
    -- Generate string in format "cluster-{number}"
    RETURN 'cluster-' || cluster_id_num::TEXT;
END;
$$ LANGUAGE plpgsql;

-- Add a new column for the string cluster_id
ALTER TABLE cluster ADD COLUMN cluster_id_new TEXT;

-- Update the new column with generated string values
UPDATE cluster SET cluster_id_new = generate_cluster_string(cluster_id);

-- Drop the old column
ALTER TABLE cluster DROP COLUMN cluster_id;

-- Rename the new column to cluster_id
ALTER TABLE cluster RENAME COLUMN cluster_id_new TO cluster_id;

-- Set NOT NULL constraint
ALTER TABLE cluster ALTER COLUMN cluster_id SET NOT NULL;

-- Clean up the temporary function
DROP FUNCTION generate_cluster_string(BIGINT);

-- Revert the attempt_cluster_upsert function to handle TEXT cluster_id
CREATE OR REPLACE FUNCTION attempt_cluster_upsert(
    cluster_id_param TEXT,
    detector_id_param INT,
    event_ids_param BIGINT[],
    sensors_param TEXT[],
    model_id_param INT,
    signature_param TEXT,
    size_param BIGINT,
    status_id_param INT,
    labels_param TEXT[],
    score_param DOUBLE PRECISION
) RETURNS VOID AS $$
BEGIN
    INSERT INTO cluster (
        cluster_id,
        detector_id,
        event_ids,
        sensors,
        model_id,
        signature,
        size,
        status_id,
        labels,
        score,
        category_id,
        qualifier_id,
        last_modification_time
    ) VALUES (
        cluster_id_param,
        detector_id_param,
        event_ids_param,
        sensors_param,
        model_id_param,
        signature_param,
        size_param,
        status_id_param,
        labels_param,
        score_param,
        1, -- Default category_id
        1, -- Default qualifier_id
        NOW()
    )
    ON CONFLICT (cluster_id, model_id) DO UPDATE SET
        detector_id = EXCLUDED.detector_id,
        event_ids = EXCLUDED.event_ids,
        sensors = EXCLUDED.sensors,
        signature = EXCLUDED.signature,
        size = EXCLUDED.size,
        status_id = EXCLUDED.status_id,
        labels = EXCLUDED.labels,
        score = EXCLUDED.score,
        last_modification_time = NOW();
END;
$$ LANGUAGE plpgsql;