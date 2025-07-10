use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_int)]
struct DescriptionInt {
    description_id: i32,
    min: Option<i64>,
    max: Option<i64>,
    mean: Option<f64>,
    s_deviation: Option<f64>,
    mode: i64,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_int)]
struct TopNInt {
    description_id: i32,
    value: i64,
    count: i64,
}
