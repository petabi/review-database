mod binary;
mod datetime;
mod r#enum;
mod float;
mod int;
mod ipaddr;
mod text;

use crate::{
    schema::{self, column_description::dsl as cd_d},
    Database, Error,
};
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use futures::future::join_all;
use serde::Serialize;
use std::{cmp::Reverse, collections::HashMap};
use structured::{ColumnStatistics, Description, ElementCount, NLargestCount};
use tracing::error;

#[derive(Debug, Queryable)]
struct ColumnDescriptionLoad {
    id: i32,
    type_id: i32,
}

#[derive(Serialize)]
pub struct Statistics {
    column_index: i32,
    statistics: ColumnStatistics,
}

trait ColumnIndex {
    fn column_index(&self) -> i32;
}

trait ToDescription {
    fn to_description(&self) -> Description;
}

trait ToElementCount {
    fn to_element_count(self) -> ElementCount;
}

trait ToNLargestCount {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount;
}

impl Database {
    /// Returns the column statistics for the given cluster and time.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn get_column_statistics(
        &self,
        cluster: i32,
        time: Vec<NaiveDateTime>,
    ) -> Result<Vec<Statistics>, Error> {
        let mut conn = self.pool.get_diesel_conn().await?;

        let mut query = cd_d::column_description
            .select((cd_d::id, cd_d::type_id))
            .filter(cd_d::cluster_id.eq(cluster))
            .order_by(cd_d::column_index.asc())
            .into_boxed();
        query = time
            .iter()
            .fold(query, |query, ts| query.or_filter(cd_d::batch_ts.eq(ts)));

        let column_info = query.load::<ColumnDescriptionLoad>(&mut conn).await?;

        let mut columns: HashMap<i32, Vec<i32>> = HashMap::new();
        for c in &column_info {
            columns.entry(c.type_id).or_default().push(c.id);
        }

        let mut results = join_all(columns.iter().map(|(type_id, description_ids)| async move {
            let conn = self.pool.get_diesel_conn().await?;
            let statistics = match type_id {
                1 => int::get_int_statistics(conn, description_ids).await,
                2 => r#enum::get_enum_statistics(conn, description_ids).await,
                3 => float::get_float_statistics(conn, description_ids).await,
                4 => text::get_text_statistics(conn, description_ids).await,
                5 => ipaddr::get_ipaddr_statistics(conn, description_ids).await,
                6 => datetime::get_datetime_statistics(conn, description_ids).await,
                7 => binary::get_binary_statistics(conn, description_ids).await,
                _ => {
                    return Err(Error::InvalidInput(format!(
                        "Unexpected column type id: {type_id}"
                    )));
                }
            };
            if let Err(e) = &statistics {
                error!("An error occurred while loading column statistics: {:?}", e);
            }
            statistics
        }))
        .await
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect::<Vec<_>>();

        results.sort_by_key(|v| v.column_index);
        Ok(results)
    }
}

fn build_column_statistics<T, U>(column_descriptions: Vec<T>, top_n: Vec<U>) -> Vec<Statistics>
where
    T: ToDescription + ToNLargestCount + ColumnIndex,
    U: ToElementCount + ColumnIndex,
{
    let element_counts = top_n_to_element_counts(top_n);
    column_descriptions
        .into_iter()
        .zip(element_counts)
        .map(|(cd, ec)| {
            let column_index = cd.column_index();
            let description = cd.to_description();
            let n_largest_count = cd.to_n_largest_count(ec);
            let cs = ColumnStatistics {
                description,
                n_largest_count,
            };
            Statistics {
                column_index,
                statistics: cs,
            }
        })
        .collect()
}

// Converts Vec<TopN> to Vec<Vec<ElementCount>>.
// Sorts the value of `count` of each `ElementCount` in descending order and the
// values of `column_index` in ascending order.
fn top_n_to_element_counts<T>(top_n: Vec<T>) -> Vec<Vec<ElementCount>>
where
    T: ToElementCount + ColumnIndex,
{
    let mut element_count = HashMap::new();
    for record in top_n {
        element_count
            .entry(record.column_index())
            .or_insert_with(Vec::new)
            .push(record.to_element_count());
    }
    let mut element_count = element_count
        .into_iter()
        .map(|mut ec| {
            ec.1.sort_by_key(|v| Reverse(v.count));
            ec
        })
        .collect::<Vec<_>>();
    element_count.sort_by_key(|v| v.0);
    element_count.into_iter().map(|(_, e)| e).collect()
}
