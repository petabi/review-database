use super::{
    schema::{cluster, time_series},
    Database, Error, Type,
};
use anyhow::anyhow;
use chrono::{Duration, NaiveDateTime, Utc};
use diesel::{
    dsl::{max, min},
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl,
};
use diesel_async::RunQueryDsl;
use futures::future::join_all;
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::error;

use cluster::dsl as c_d;
use time_series::dsl as t_d;

const MAX_CSV_COLUMNS: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TimeSeries {
    count_index: Option<usize>, // if None, count just rows. If Some, count values of the column.
    series: Vec<TimeCount>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, Serialize)]
pub struct TimeSeriesUpdate {
    cluster_id: String,
    time: NaiveDateTime,
    time_series: Vec<TimeSeries>,
}

#[derive(Debug, Queryable)]
struct TimeSeriesLoad {
    _time: NaiveDateTime, // round
    count_index: Option<i32>,
    value: NaiveDateTime,
    count: i64,
}

#[derive(Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct TimeSeriesResult {
    pub earliest: Option<NaiveDateTime>,
    pub latest: Option<NaiveDateTime>,
    pub series: Vec<ColumnTimeSeries>,
}

#[derive(Clone, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ColumnTimeSeries {
    pub column_index: usize,
    pub series: Vec<TimeCount>,
}

// Frontend uses count of usize
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeCount {
    pub time: NaiveDateTime,
    pub count: usize,
}

pub(crate) fn fill_vacant_time_slots(series: &[TimeCount]) -> Vec<TimeCount> {
    let mut filled_series: Vec<TimeCount> = Vec::new();

    if series.len() <= 2 {
        return series.to_vec();
    }

    let mut min_diff = series[1].time - series[0].time;
    for index in 2..series.len() {
        let diff = series[index].time - series[index - 1].time;
        if diff < min_diff {
            min_diff = diff;
        }
    }

    for (index, element) in series.iter().enumerate() {
        if index == 0 {
            filled_series.push(element.clone());
            continue;
        }
        let time_diff =
            (element.time - series[index - 1].time).num_seconds() / min_diff.num_seconds();
        if time_diff > 1 {
            for d in 1..time_diff {
                filled_series.push(TimeCount {
                    time: series[index - 1].time + Duration::seconds(d * min_diff.num_seconds()),
                    count: 0,
                });
            }
        }
        filled_series.push(element.clone());
    }
    filled_series
}

impl Database {
    /// Adds a time series for the given model.
    ///
    /// # Panics
    ///
    /// Will panic if `MAX_CSV_COLUMNS` exceeds `i32::MAX`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub async fn add_time_series(
        &self,
        time_series: Vec<TimeSeriesUpdate>,
        model: i32,
    ) -> Result<(), anyhow::Error> {
        let tasks = time_series.into_iter().map(|ts| async move {
            let cluster_id = self.cluster_id(&ts.cluster_id, model).await?;

            let time = ts.time;
            let tasks = ts.time_series.into_iter().map(move |s| {
                let count_index = s.count_index;
                let tasks = s.series.into_iter().map(move |tc| async move {
                    let conn = self.pool.get().await?;
                    conn.insert_into(
                        "time_series",
                        &[
                            ("cluster_id", Type::INT4),
                            ("time", Type::TIMESTAMP),
                            ("count_index", Type::INT4),
                            ("value", Type::TIMESTAMP),
                            ("count", Type::INT8),
                        ],
                        &[
                            &cluster_id,
                            &time,
                            &count_index.map(|c| {
                                std::cmp::min(c, MAX_CSV_COLUMNS)
                                    .to_i32()
                                    .expect("less than i32::MAX")
                            }),
                            &tc.time,
                            &i64::from_usize(tc.count).unwrap_or(i64::MAX),
                        ],
                    )
                    .await
                });
                join_all(tasks)
            });
            Ok(join_all(tasks).await) as Result<_, Error>
        });
        if join_all(tasks).await.into_iter().all(|r| r.is_ok()) {
            Ok(())
        } else {
            error!("failed to insert time series");
            Err(anyhow!("failed to insert the entire time series"))
        }
    }

    /// Returns the time range of time series for the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub async fn get_time_range_of_model(
        &self,
        model_id: i32,
    ) -> Result<(Option<NaiveDateTime>, Option<NaiveDateTime>), Error> {
        let mut conn = self.pool.get_diesel_conn().await?;
        Ok(c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select((min(t_d::value), max(t_d::value)))
            .filter(c_d::model_id.eq(model_id))
            .get_result(&mut conn)
            .await?)
    }

    /// Gets the top time series of the given cluster.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub async fn get_top_time_series_of_cluster(
        &self,
        model_id: i32,
        cluster_id: &str,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<TimeSeriesResult, Error> {
        let mut conn = self.pool.get_diesel_conn().await?;
        let (earliest, latest) = c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select((min(t_d::value), max(t_d::value)))
            .filter(
                c_d::model_id
                    .eq(model_id)
                    .and(c_d::cluster_id.eq(cluster_id)),
            )
            .get_result::<(Option<NaiveDateTime>, Option<NaiveDateTime>)>(&mut conn)
            .await?;
        let recent = latest.unwrap_or_else(|| Utc::now().naive_utc());

        let (start, end) = if let (Some(start), Some(end)) = (start, end) {
            match (
                NaiveDateTime::from_timestamp_opt(start, 0),
                NaiveDateTime::from_timestamp_opt(end, 0),
            ) {
                (Some(s), Some(e)) => (s, e),
                _ => {
                    return Err(Error::InvalidInput(format!(
                        "illegal time range provided({start}, {end})"
                    )))
                }
            }
        } else {
            (recent - Duration::hours(2), recent)
        };

        let values = c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select((t_d::time, t_d::count_index, t_d::value, t_d::count))
            .filter(
                c_d::model_id
                    .eq(model_id)
                    .and(c_d::cluster_id.eq(cluster_id))
                    .and(t_d::value.gt(start)) // HIGHLIGHT: first and last items should not be included because they might have insufficient counts.
                    .and(t_d::value.lt(end)),
            )
            .load::<TimeSeriesLoad>(&mut conn)
            .await?;

        let mut series: HashMap<usize, HashMap<NaiveDateTime, i64>> = HashMap::new();
        for v in values {
            let (count_index, value, count) = (
                v.count_index
                    .map_or(100_000, |c| c.to_usize().expect("safe: positive")),
                // 100_000 means counting events themselves, not any other column values.
                v.value,
                v.count,
            );

            *series
                .entry(count_index)
                .or_default()
                .entry(value)
                .or_insert(0) += count;
        }

        let mut series: Vec<ColumnTimeSeries> = series
            .into_iter()
            .filter_map(|(column_index, top_n)| {
                if top_n.is_empty() {
                    None
                } else {
                    let mut series: Vec<TimeCount> = top_n
                        .into_iter()
                        .map(|(dt, count)| TimeCount {
                            time: dt,
                            count: count.to_usize().unwrap_or(usize::MAX),
                        })
                        .collect();
                    series.sort_by_key(|v| v.time);
                    let series = fill_vacant_time_slots(&series);

                    Some(ColumnTimeSeries {
                        column_index,
                        series,
                    })
                }
            })
            .collect();
        series.sort_by_key(|v| v.column_index);

        Ok(TimeSeriesResult {
            earliest,
            latest,
            series,
        })
    }
}
