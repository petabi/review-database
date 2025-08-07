use chrono::NaiveDateTime;
use diesel::sql_types::{BigInt, Integer, Text, Timestamp};
use serde::{Deserialize, Serialize};

use super::TopElementCountsByColumn;

#[derive(Debug, QueryableByName, Serialize)]
#[allow(dead_code)]
pub struct SelectedCluster {
    #[diesel(sql_type = Integer)]
    model_id: i32,
    #[diesel(sql_type = Integer)]
    column_index: i32,
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Timestamp)]
    batch_ts: NaiveDateTime,
    #[diesel(sql_type = Integer)]
    description_id: i32,
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(Deserialize)]
pub struct TopColumnsOfCluster {
    pub cluster_id: String,
    pub columns: Vec<TopElementCountsByColumn>,
}

#[derive(Deserialize)]
pub struct TopMultimaps {
    pub n_index: usize,
    pub selected: Vec<TopColumnsOfCluster>,
}
