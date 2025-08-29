// @generated automatically by Diesel CLI.

diesel::table! {
    cluster (id) {
        id -> Int4,
        category_id -> Int4,
        cluster_id -> Text,
        detector_id -> Int4,
        event_ids -> Array<Nullable<Int8>>,
        labels -> Nullable<Array<Nullable<Text>>>,
        last_modification_time -> Nullable<Timestamp>,
        model_id -> Int4,
        qualifier_id -> Int4,
        score -> Nullable<Float8>,
        signature -> Text,
        size -> Int8,
        status_id -> Int4,
        sensors -> Array<Nullable<Text>>,
    }
}

diesel::table! {
    model (id) {
        id -> Int4,
        name -> Text,
        kind -> Text,
        max_event_id_num -> Int4,
        data_source_id -> Int4,
        classifier -> Nullable<Bytea>,
        classification_id -> Nullable<Int8>,
        version -> Int4,
    }
}

diesel::table! {
    time_series (id) {
        id -> Int4,
        cluster_id -> Int4,
        time -> Timestamp,
        count_index -> Nullable<Int4>,
        value -> Timestamp,
        count -> Int8,
    }
}

diesel::allow_tables_to_appear_in_same_query!(cluster, model, time_series,);
