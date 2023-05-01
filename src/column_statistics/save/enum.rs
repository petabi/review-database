use crate::{
    schema::{description_enum::dsl as desc_d, top_n_enum::dsl as topn_d},
    Error,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

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

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &str,
) -> Result<(), Error> {
    let db = DescriptionEnum {
        description_id,
        mode,
    };
    let _query = diesel::insert_into(desc_d::description_enum)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let value = if let Element::Enum(val) = &e.value {
                val.as_str()
            } else {
                return None;
            };
            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNEnum {
                description_id,
                value,
                count,
            })
        })
        .collect();
    let res = diesel::insert_into(topn_d::top_n_enum)
        .values(&top_n)
        .execute(conn)
        .await?;
    if res != column_stats.n_largest_count.top_n().len() {
        error!(
            "Failed to insert all of top_n_enum, entries failed: {} / {}",
            column_stats.n_largest_count.top_n().len() - res,
            column_stats.n_largest_count.top_n().len()
        );
    }
    Ok(())
}
