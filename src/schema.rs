table! {
    category (id) {
        id -> Int4,
        name -> Text,
    }
}

table! {
    cluster (id) {
        id -> Int4,
        cluster_id -> Text,
        category_id -> Int4,
        detector_id -> Int4,
        event_ids -> Array<Int8>,
        qualifier_id -> Int4,
        status_id -> Int4,
        signature -> Text,
        size -> Int8,
        score -> Nullable<Float8>,
        model_id -> Int4,
        last_modification_time -> Nullable<Timestamp>,
    }
}

table! {
    column_description (id) {
        id -> Int4,
        event_range_id -> Int4,
        column_index -> Int4,
        type_id -> Int4,
        count -> Int8,
        unique_count -> Int8,
    }
}

table! {
    csv_column_extra (id) {
        id -> Int4,
        model_id -> Int4,
        column_alias -> Nullable<Array<Text>>,
        column_display -> Nullable<Array<Bool>>,
        column_top_n -> Nullable<Array<Bool>>,
        column_1 -> Nullable<Array<Bool>>,
        column_n -> Nullable<Array<Bool>>,
    }
}

table! {
    csv_column_list (id) {
        id -> Int4,
        model_id -> Int4,
        column_indicator -> Nullable<Array<Text>>,
        column_whitelist -> Nullable<Array<Text>>,
    }
}

table! {
    csv_indicator (id) {
        id -> Int4,
        name -> Text,
        description -> Nullable<Text>,
        list -> Text,
        last_modification_time -> Nullable<Timestamp>,
    }
}

table! {
    csv_whitelist (id) {
        id -> Int4,
        name -> Text,
        description -> Nullable<Text>,
        list -> Text,
        last_modification_time -> Nullable<Timestamp>,
    }
}

table! {
    description_binary (id) {
        id -> Int4,
        description_id -> Int4,
        mode -> Bytea,
    }
}

table! {
    description_datetime (id) {
        id -> Int4,
        description_id -> Int4,
        mode -> Timestamp,
    }
}

table! {
    description_enum (id) {
        id -> Int4,
        description_id -> Int4,
        mode -> Text,
    }
}

table! {
    description_float (id) {
        id -> Int4,
        description_id -> Int4,
        min -> Nullable<Float8>,
        max -> Nullable<Float8>,
        mean -> Nullable<Float8>,
        s_deviation -> Nullable<Float8>,
        mode_smallest -> Float8,
        mode_largest -> Float8,
    }
}

table! {
    description_int (id) {
        id -> Int4,
        description_id -> Int4,
        min -> Nullable<Int8>,
        max -> Nullable<Int8>,
        mean -> Nullable<Float8>,
        s_deviation -> Nullable<Float8>,
        mode -> Int8,
    }
}

table! {
    description_ipaddr (id) {
        id -> Int4,
        description_id -> Int4,
        mode -> Text,
    }
}

table! {
    description_text (id) {
        id -> Int4,
        description_id -> Int4,
        mode -> Text,
    }
}

table! {
    event_range (id) {
        id -> Int4,
        cluster_id -> Int4,
        time -> Timestamp,
        first_event_id -> Int8,
        last_event_id -> Int8,
    }
}

table! {
    model (id) {
        id -> Int4,
        name -> Text,
        kind -> Text,
        max_event_id_num -> Int4,
        data_source_id -> Int4,
        classifier -> Bytea,
    }
}

table! {
    outlier (id) {
        id -> Int4,
        raw_event -> Bytea,
        model_id -> Int4,
        event_ids -> Array<Int8>,
        size -> Int8,
    }
}

table! {
    qualifier (id) {
        id -> Int4,
        description -> Text,
    }
}

table! {
    status (id) {
        id -> Int4,
        description -> Text,
    }
}

table! {
    time_series (id) {
        id -> Int4,
        cluster_id -> Int4,
        time -> Timestamp,
        count_index -> Nullable<Int4>,
        value -> Timestamp,
        count -> Int8,
    }
}

table! {
    top_n_binary (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Bytea,
        count -> Int8,
    }
}

table! {
    top_n_datetime (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Timestamp,
        count -> Int8,
    }
}

table! {
    top_n_enum (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Text,
        count -> Int8,
    }
}

table! {
    top_n_float (id) {
        id -> Int4,
        description_id -> Int4,
        value_smallest -> Float8,
        value_largest -> Float8,
        count -> Int8,
    }
}

table! {
    top_n_int (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Int8,
        count -> Int8,
    }
}

table! {
    top_n_ipaddr (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Text,
        count -> Int8,
    }
}

table! {
    top_n_text (id) {
        id -> Int4,
        description_id -> Int4,
        value -> Text,
        count -> Int8,
    }
}

allow_tables_to_appear_in_same_query!(
    category,
    cluster,
    column_description,
    csv_column_extra,
    csv_column_list,
    csv_indicator,
    csv_whitelist,
    description_binary,
    description_datetime,
    description_enum,
    description_float,
    description_int,
    description_ipaddr,
    description_text,
    event_range,
    model,
    outlier,
    qualifier,
    status,
    time_series,
    top_n_binary,
    top_n_datetime,
    top_n_enum,
    top_n_float,
    top_n_int,
    top_n_ipaddr,
    top_n_text,
);
