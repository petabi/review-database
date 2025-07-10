use chrono::NaiveDateTime;
use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_datetime)]
struct DescriptionDatetime {
    description_id: i32,
    mode: NaiveDateTime,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_datetime)]
struct TopNDatetime {
    description_id: i32,
    value: NaiveDateTime,
    count: i64,
}
