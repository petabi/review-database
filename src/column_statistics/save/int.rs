use std::convert::TryFrom;

use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use structured::{ColumnStatistics, Element};

use crate::{
    schema::{description_int::dsl as desc_d, top_n_int::dsl as topn_d},
    Error,
};

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

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: i64,
) -> Result<usize, Error> {
    let min = if let Some(Element::Int(v)) = column_stats.description.min() {
        Some(*v)
    } else {
        None
    };
    let max = if let Some(Element::Int(v)) = column_stats.description.max() {
        Some(*v)
    } else {
        None
    };

    let db = DescriptionInt {
        description_id,
        min,
        max,
        mean: column_stats.description.mean(),
        s_deviation: column_stats.description.std_deviation(),
        mode,
    };
    let _res = diesel::insert_into(desc_d::description_int)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let value = if let Element::Int(val) = &e.value {
                *val
            } else {
                return None;
            };
            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNInt {
                description_id,
                value,
                count,
            })
        })
        .collect();
    Ok(diesel::insert_into(topn_d::top_n_int)
        .values(&top_n)
        .execute(conn)
        .await?)
}
