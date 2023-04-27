use crate::{
    schema::{description_text::dsl as desc_d, top_n_text::dsl as topn_d},
    Error,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

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

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &str,
) -> Result<(), Error> {
    let db = DescriptionText {
        description_id,
        mode,
    };
    let _res = diesel::insert_into(desc_d::description_text)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let value = if let Element::Text(val) = &e.value {
                val.as_str()
            } else {
                return None;
            };
            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNText {
                description_id,
                value,
                count,
            })
        })
        .collect();
    let res = diesel::insert_into(topn_d::top_n_text)
        .values(&top_n)
        .execute(conn)
        .await?;
    if res != column_stats.n_largest_count.top_n().len() {
        error!(
            "Failed to insert all of top_n_binary, entries failed: {} / {}",
            column_stats.n_largest_count.top_n().len() - res,
            column_stats.n_largest_count.top_n().len()
        );
    }
    Ok(())
}
