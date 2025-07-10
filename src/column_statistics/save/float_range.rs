use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_float)]
struct DescriptionFloat {
    description_id: i32,
    min: Option<f64>,
    max: Option<f64>,
    mean: Option<f64>,
    s_deviation: Option<f64>,
    mode_smallest: f64,
    mode_largest: f64,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_float)]
struct TopNFloat {
    description_id: i32,
    value_smallest: f64,
    value_largest: f64,
    count: i64,
}
