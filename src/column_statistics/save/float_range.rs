use crate::{
    schema::{description_float::dsl as desc_d, top_n_float::dsl as topn_d},
    Error,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Deserialize;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element, FloatRange};
use tracing::error;

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::description_float)]
struct DescriptionFloat {
    description_id: i32,
    min: Option<f64>,
    max: Option<f64>,
    mean: Option<f64>,
    s_deviation: Option<f64>,
    mode_smallest: f64,
    mode_largest: f64,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::top_n_float)]
struct TopNFloat {
    description_id: i32,
    value_smallest: f64,
    value_largest: f64,
    count: i64,
}

pub(super) async fn insert_top_n(
    conn: &mut AsyncPgConnection,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &FloatRange,
) -> Result<(), Error> {
    let min = if let Some(Element::Float(min)) = &column_stats.description.min() {
        Some(*min)
    } else {
        None
    };
    let max = if let Some(Element::Float(max)) = &column_stats.description.max() {
        Some(*max)
    } else {
        None
    };

    let db = DescriptionFloat {
        description_id,
        min,
        max,
        mean: column_stats.description.mean(),
        s_deviation: column_stats.description.std_deviation(),
        mode_smallest: mode.smallest,
        mode_largest: mode.largest,
    };
    let _query = diesel::insert_into(desc_d::description_float)
        .values(&db)
        .execute(conn)
        .await?;

    let top_n: Vec<_> = column_stats
        .n_largest_count
        .top_n()
        .iter()
        .filter_map(|e| {
            let (value_smallest, value_largest) = if let Element::FloatRange(fr) = &e.value {
                (fr.smallest, fr.largest)
            } else {
                return None;
            };
            let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
            Some(TopNFloat {
                description_id,
                value_smallest,
                value_largest,
                count,
            })
        })
        .collect();
    let res = diesel::insert_into(topn_d::top_n_float)
        .values(&top_n)
        .execute(conn)
        .await?;
    if res != column_stats.n_largest_count.top_n().len() {
        error!(
            "Failed to insert all of top_n_float, entries failed: {} / {}",
            column_stats.n_largest_count.top_n().len() - res,
            column_stats.n_largest_count.top_n().len()
        );
    }
    Ok(())
}
