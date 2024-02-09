use super::{binary, datetime, float_range, int, ipaddr, r#enum, text};
use crate::schema::{cluster::dsl as cluster_d, column_description::dsl as cd_d};
use crate::Database;
use anyhow::Result;
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde::Deserialize;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize)]
pub struct ColumnStatisticsUpdate {
    cluster_id: String, // NOT cluster_id but id of cluster table
    column_statistics: Vec<ColumnStatistics>,
}

#[derive(Deserialize, Debug, Insertable, PartialEq)]
#[diesel(table_name = crate::schema::column_description)]
struct ColumnDescriptionInput {
    column_index: i32,
    type_id: i32,
    count: i64,
    unique_count: i64,
    cluster_id: i32,
    batch_ts: NaiveDateTime,
}

#[derive(Deserialize, Debug, Insertable, PartialEq, Identifiable, Queryable)]
#[diesel(table_name = crate::schema::column_description)]
struct ColumnDescription {
    id: i32,
    column_index: i32,
    type_id: i32,
    count: i64,
    unique_count: i64,
    cluster_id: i32,
    batch_ts: NaiveDateTime,
}

fn check_column_types(stats: &[ColumnStatisticsUpdate]) -> Vec<Option<i32>> {
    stats
        .first()
        .map(|stat| {
            stat.column_statistics
                .iter()
                .map(|column_stats| match &column_stats.n_largest_count.mode() {
                    Some(Element::Int(_)) => Some(1),
                    Some(Element::Enum(_)) => Some(2),
                    Some(Element::FloatRange(_)) => Some(3),
                    Some(Element::Text(_)) => Some(4),
                    Some(Element::IpAddr(_)) => Some(5),
                    Some(Element::DateTime(_)) => Some(6),
                    Some(Element::Binary(_)) => Some(7),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

impl Database {
    /// Inserts column statistics into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn insert_column_statistics(
        &self,
        statistics: Vec<ColumnStatisticsUpdate>,
        model_id: i32,
        batch_ts: NaiveDateTime,
    ) -> Result<()> {
        let mut conn = self.pool.get_diesel_conn().await?;

        let column_types = check_column_types(&statistics);
        if column_types.is_empty() {
            anyhow::bail!("Unsupported column type");
        }
        for stat in statistics {
            let query = cluster_d::cluster.select(cluster_d::id).filter(
                cluster_d::model_id
                    .eq(model_id)
                    .and(cluster_d::cluster_id.eq(stat.cluster_id)),
            );
            let cluster_id = query.load::<i32>(&mut conn).await?[0];

            let column_descriptions: Vec<_> = (0..)
                .zip(&column_types)
                .zip(&stat.column_statistics)
                .filter_map(|((column_index, &type_id), column_stats)| {
                    if let Some(type_id) = type_id {
                        let count =
                            i64::try_from(column_stats.description.count()).unwrap_or_default();
                        let unique_count =
                            i64::try_from(column_stats.n_largest_count.number_of_elements())
                                .unwrap_or_default();
                        Some(ColumnDescriptionInput {
                            column_index,
                            type_id,
                            count,
                            unique_count,
                            cluster_id,
                            batch_ts,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let query = diesel::insert_into(cd_d::column_description).values(&column_descriptions);
            let column_descriptions: Vec<ColumnDescription> = query.get_results(&mut conn).await?;
            for (id, column_stats) in
                column_descriptions
                    .into_iter()
                    .filter_map(|c: ColumnDescription| {
                        if let Ok(cid) = usize::try_from(c.column_index) {
                            Some((c.id, &stat.column_statistics[cid]))
                        } else {
                            None
                        }
                    })
            {
                let (type_name, inserted) = match &column_stats.n_largest_count.mode() {
                    Some(Element::Int(mode)) => (
                        "int",
                        int::insert_top_n(&mut conn, id, column_stats, *mode).await?,
                    ),
                    Some(Element::Enum(mode)) => (
                        "enum",
                        r#enum::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    Some(Element::FloatRange(mode)) => (
                        "float_range",
                        float_range::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    Some(Element::Text(mode)) => (
                        "text",
                        text::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    Some(Element::IpAddr(mode)) => (
                        "ipaddr",
                        ipaddr::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    Some(Element::DateTime(mode)) => (
                        "datetime",
                        datetime::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    Some(Element::Binary(mode)) => (
                        "binary",
                        binary::insert_top_n(&mut conn, id, column_stats, mode).await?,
                    ),
                    _ => ("", column_stats.n_largest_count.top_n().len()),
                };
                if inserted != column_stats.n_largest_count.top_n().len() {
                    tracing::error!(
                        "Failed to insert all of top_n {}, entries failed: {} / {}",
                        type_name,
                        column_stats.n_largest_count.top_n().len() - inserted,
                        column_stats.n_largest_count.top_n().len()
                    );
                }
            }
        }
        Ok(())
    }
}
