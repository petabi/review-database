use chrono::NaiveDateTime;
use serde::Deserialize;
use structured::ColumnStatistics;

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize)]
pub struct ColumnStatisticsUpdate {
    pub cluster_id: String, // NOT cluster_id but id of cluster table
    pub column_statistics: Vec<ColumnStatistics>,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::column_description)]
struct ColumnDescriptionInput {
    column_index: i32,
    type_id: i32,
    count: i64,
    unique_count: i64,
    cluster_id: i32,
    batch_ts: NaiveDateTime,
}

#[derive(Deserialize, Debug, Insertable, PartialEq, Identifiable, Queryable)]
#[diesel(table_name = crate::schema::column_description)]
struct ColumnDescription {
    id: i32,
    column_index: i32,
    type_id: i32,
    count: i64,
    unique_count: i64,
    cluster_id: i32,
    batch_ts: NaiveDateTime,
}
