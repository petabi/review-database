use serde::Deserialize;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_ipaddr)]
struct DescriptionIpaddr {
    description_id: i32,
    mode: String,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_ipaddr)]
struct TopNIpaddr {
    description_id: i32,
    value: String,
    count: i64,
}
