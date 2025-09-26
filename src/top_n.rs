mod time_series;

use serde::{Deserialize, Serialize};

#[allow(deprecated)]
pub use self::time_series::{ClusterTrend, LineSegment, Regression, TopTrendsByColumn};

impl From<(i32, i32)> for StructuredColumnType {
    fn from((column_index, type_id): (i32, i32)) -> Self {
        let data_type = match type_id {
            1 => "int64",
            2 => "enum",
            3 => "float64",
            4 => "utf8",
            5 => "ipaddr",
            6 => "datetime",
            7 => "binary",
            _ => unreachable!(),
        };
        Self {
            column_index,
            data_type: data_type.to_string(),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct ElementCount {
    pub value: String,
    pub count: i64,
}

#[derive(Deserialize, Serialize)]
pub struct StructuredColumnType {
    pub column_index: i32,
    pub data_type: String,
}

#[derive(Clone, Deserialize)]
pub struct TopElementCountsByColumn {
    pub column_index: usize,
    pub counts: Vec<ElementCount>,
}
