-- Change cluster_id from TEXT to BIGINT in cluster table
-- This migration converts string cluster_ids (format: "prefix-number") to numerical ids

-- First, create a temporary function to extract numerical part from cluster_id strings
CREATE OR REPLACE FUNCTION extract_cluster_number(cluster_id_str TEXT) RETURNS BIGINT AS $$
DECLARE
    parts TEXT[];
    number_part TEXT;
BEGIN
    -- Split by '-' and get the last part
    parts := string_to_array(cluster_id_str, '-');
    number_part := parts[array_length(parts, 1)];
    
    -- Try to convert to BIGINT, return 0 if conversion fails
    BEGIN
        RETURN number_part::BIGINT;
    EXCEPTION WHEN OTHERS THEN
        RETURN 0;
    END;
END;
$$ LANGUAGE plpgsql;

-- Add a new column for the numerical cluster_id
ALTER TABLE cluster ADD COLUMN cluster_id_new BIGINT;

-- Update the new column with extracted numerical values
UPDATE cluster SET cluster_id_new = extract_cluster_number(cluster_id);

-- Drop the old column
ALTER TABLE cluster DROP COLUMN cluster_id;

-- Rename the new column to cluster_id
ALTER TABLE cluster RENAME COLUMN cluster_id_new TO cluster_id;

-- Set NOT NULL constraint (assuming cluster_id should not be null)
ALTER TABLE cluster ALTER COLUMN cluster_id SET NOT NULL;

-- Clean up the temporary function
DROP FUNCTION extract_cluster_number(TEXT);

-- Update the attempt_cluster_upsert function to handle BIGINT cluster_id instead of TEXT
CREATE OR REPLACE FUNCTION attempt_cluster_upsert(
    cluster_id_param BIGINT,
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