use super::{binary, datetime, float_range, int, ipaddr, r#enum, text};
use crate::{Database, Type};
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use futures::future::join_all;
use serde::Deserialize;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

#[derive(Deserialize)]
pub struct ColumnStatisticsUpdate {
    cluster_id: String, // NOT cluster_id but id of cluster table
    time: NaiveDateTime,
    first_event_id: u64,
    last_event_id: u64,
    column_statistics: Vec<ColumnStatistics>,
}

fn check_column_types(stats: &[ColumnStatisticsUpdate]) -> Vec<i32> {
    stats
        .first()
        .map(|stat| {
            stat.column_statistics
                .iter()
                .filter_map(|column_stats| match &column_stats.n_largest_count.mode() {
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
    #[allow(clippy::too_many_lines)]
    pub async fn insert_column_statistics(
        &self,
        statistics: Vec<ColumnStatisticsUpdate>,
        model_id: i32,
    ) -> Result<()> {
        let column_types = check_column_types(&statistics);
        if column_types.is_empty() {
            anyhow::bail!("Unsupported column type");
        }
        join_all(
            statistics
                .into_iter()
                .map(|stat| {
                    let client = self.pool.clone();
                    let column_types_cloned = column_types.clone();
                    tokio::spawn(async move {
                        let mut conn = client.get().await?;
                        let txn = conn.build_transaction().await?;

                        let first_event_id = i64::try_from(stat.first_event_id)
                            .context("must be less than i64::MAX")?;
                        let last_event_id = i64::try_from(stat.last_event_id)
                            .context("must be less than i64::MAX")?;
                        let cluster_id: i32 = txn
                            .select_one_from(
                                "cluster",
                                &["id"],
                                &[("cluster_id", Type::TEXT), ("model_id", Type::INT4)],
                                &[&stat.cluster_id, &model_id],
                            )
                            .await?
                            .get(0);
                        let event_range_id = txn
                            .insert_into(
                                "event_range",
                                &[
                                    ("time", Type::TIMESTAMP),
                                    ("first_event_id", Type::INT8),
                                    ("last_event_id", Type::INT8),
                                    ("cluster_id", Type::INT4),
                                ],
                                &[&stat.time, &first_event_id, &last_event_id, &cluster_id],
                            )
                            .await
                            .context("failed to insert event range")?;

                        for ((column_index, type_id), column_stats) in
                            (0..).zip(&column_types_cloned).zip(&stat.column_statistics)
                        {
                            let count =
                                i64::try_from(column_stats.description.count()).unwrap_or_default();
                            let unique_count =
                                i64::try_from(column_stats.n_largest_count.number_of_elements())
                                    .unwrap_or_default();
                            let id = match txn
                                .insert_into(
                                    "column_description",
                                    &[
                                        ("event_range_id", Type::INT4),
                                        ("column_index", Type::INT4),
                                        ("type_id", Type::INT4),
                                        ("count", Type::INT8),
                                        ("unique_count", Type::INT8),
                                    ],
                                    &[
                                        &event_range_id,
                                        &column_index,
                                        &type_id,
                                        &count,
                                        &unique_count,
                                    ],
                                )
                                .await
                            {
                                Ok(id) => id,
                                Err(e) => {
                                    error!("failed to insert column_description: {:#}", e);
                                    continue;
                                }
                            };

                            match &column_stats.n_largest_count.mode() {
                                Some(Element::Int(mode)) => {
                                    int::insert_int(&txn, id, column_stats, *mode).await;
                                }
                                Some(Element::Enum(mode)) => {
                                    r#enum::insert_enum(&txn, id, column_stats, mode).await;
                                }
                                Some(Element::FloatRange(mode)) => {
                                    float_range::insert_float(&txn, id, column_stats, mode).await;
                                }
                                Some(Element::Text(mode)) => {
                                    text::insert_text(&txn, id, column_stats, mode).await;
                                }
                                Some(Element::IpAddr(mode)) => {
                                    ipaddr::insert_ipaddr(&txn, id, column_stats, mode).await;
                                }
                                Some(Element::DateTime(mode)) => {
                                    datetime::insert_datetime(&txn, id, column_stats, mode).await;
                                }
                                Some(Element::Binary(mode)) => {
                                    binary::insert_binary(&txn, id, column_stats, mode).await;
                                }
                                _ => {}
                            }
                        }

                        txn.commit().await?;
                        anyhow::Ok(())
                    })
                })
                .map(|task| async move {
                    match task.await {
                        Ok(Err(e)) => {
                            error!(
                                "An error occurred while inserting column statistics: {:#}",
                                e
                            );
                        }
                        Err(e) => error!("Failed to execute insert_column_statistics: {:#}", e),
                        _ => {}
                    }
                }),
        )
        .await;
        Ok(())
    }
}
