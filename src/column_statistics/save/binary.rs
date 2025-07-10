use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_binary)]
struct DescriptionBinary<'a> {
    description_id: i32,
    mode: &'a [u8],
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_binary)]
struct TopNBinary<'a> {
    description_id: i32,
    value: Option<&'a [u8]>,
    count: i64,
}
