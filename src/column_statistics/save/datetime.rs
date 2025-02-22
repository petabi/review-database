use std::convert::TryFrom;

use chrono::NaiveDateTime;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use structured::{ColumnStatistics, Element};

use crate::{
    Error,
    schema::{description_datetime::dsl as desc_d, top_n_datetime::dsl as topn_d},
};

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_datetime)]
struct DescriptionDatetime {
    description_id: i32,
    mode: NaiveDateTime,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_datetime)]
struct TopNDatetime {
    description_id: i32,
    value: NaiveDateTime,
    count: i64,
}

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &NaiveDateTime,
) -> Result<usize, Error> {
    let db = DescriptionDatetime {
        description_id,
        mode: *mode,
    };
    let _res = diesel::insert_into(desc_d::description_datetime)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let value = if let Element::DateTime(datetime) = &e.value {
                *datetime
            } else {
                return None;
            };
            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNDatetime {
                description_id,
                value,
                count,
            })
        })
        .collect();
    Ok(diesel::insert_into(topn_d::top_n_datetime)
        .values(&top_n)
        .execute(conn)
        .await?)
}
