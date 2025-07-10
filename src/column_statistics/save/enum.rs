use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_enum)]
struct DescriptionEnum<'a> {
    description_id: i32,
    mode: &'a str,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_enum)]
struct TopNEnum<'a> {
    description_id: i32,
    value: &'a str,
    count: i64,
}
