use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_text)]
struct DescriptionText<'a> {
    description_id: i32,
    mode: &'a str,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_text)]
struct TopNText<'a> {
    description_id: i32,
    value: &'a str,
    count: i64,
}
