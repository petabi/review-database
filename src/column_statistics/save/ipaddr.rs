use std::convert::TryFrom;

use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use structured::{ColumnStatistics, Element};

use crate::{
    Error,
    schema::{description_ipaddr::dsl as desc_d, top_n_ipaddr::dsl as topn_d},
};

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

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &std::net::IpAddr,
) -> Result<usize, Error> {
    let mode = mode.to_string();

    let db = DescriptionIpaddr {
        description_id,
        mode,
    };
    let _res = diesel::insert_into(desc_d::description_ipaddr)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let value = if let Element::IpAddr(val) = &e.value {
                val.to_string()
            } else {
                return None;
            };

            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNIpaddr {
                description_id,
                value,
                count,
            })
        })
        .collect();
    Ok(diesel::insert_into(topn_d::top_n_ipaddr)
        .values(&top_n)
        .execute(conn)
        .await?)
}
