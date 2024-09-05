use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use diesel::{
    dsl::{max, min},
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl,
};
use diesel_async::RunQueryDsl;
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::{
    schema::{cluster::dsl as c_d, time_series::dsl as t_d},
    Database, Error,
};

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

pub(crate) fn fill_vacant_time_slots(series: &[TimeCount]) -> Option<Vec<TimeCount>> {
    let mut filled_series: Vec<TimeCount> = Vec::new();

    if series.len() <= 2 {
        return Some(series.to_vec());
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
                    time: series[index - 1].time
                        + Duration::try_seconds(d * min_diff.num_seconds())?,
                    count: 0,
                });
            }
        }
        filled_series.push(element.clone());
    }
    Some(filled_series)
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
        model_id: i32,
        batch_ts: NaiveDateTime,
    ) -> Result<()> {
        // Execute 100 insertion per transaction since each TimeSeries requires
        // the insertion of multiple TimeCount.
        let mut chunks: Vec<Vec<TimeSeriesUpdate>> =
            Vec::with_capacity(time_series.len() / 100 + 1);
        let mut peekable = time_series.into_iter().peekable();
        while peekable.peek().is_some() {
            chunks.push(peekable.by_ref().take(100).collect::<Vec<_>>());
        }

        let mut tasks = tokio::task::JoinSet::new();

        for chunk in chunks {
            let pool = self.pool.clone();
            tasks.spawn(async move {
                let mut conn = pool.get_diesel_conn().await?;
                conn.build_transaction()
                    .run(move |conn| {
                        Box::pin(async move {
                            for ts in chunk {
                                let cluster_id: i32 = c_d::cluster
                                    .select(c_d::id)
                                    .filter(
                                        c_d::cluster_id
                                            .eq(&ts.cluster_id)
                                            .and(c_d::model_id.eq(model_id)),
                                    )
                                    .get_result(conn)
                                    .await?;
                                for s in ts.time_series {
                                    let count_index = s.count_index.map(|c| {
                                        std::cmp::min(c, MAX_CSV_COLUMNS)
                                            .to_i32()
                                            .expect("less than i32::MAX")
                                    });
                                    for tc in s.series {
                                        diesel::insert_into(t_d::time_series)
                                            .values((
                                                t_d::cluster_id.eq(&cluster_id),
                                                t_d::time.eq(&batch_ts),
                                                t_d::count_index.eq(&count_index),
                                                t_d::value.eq(&tc.time),
                                                t_d::count
                                                    .eq(&i64::from_usize(tc.count)
                                                        .unwrap_or(i64::MAX)),
                                            ))
                                            .execute(conn)
                                            .await?;
                                    }
                                }
                            }
                            Ok::<_, Error>(())
                        })
                    })
                    .await?;
                anyhow::Ok(())
            });
        }
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(Err(e)) => {
                    error!("An error occurred while inserting time_series: {e:#}");
                }
                Err(e) => error!("Failed to execute insertion of time_series: {e:#}"),
                _ => {}
            }
        }

        Ok(())
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
        let recent: NaiveDateTime = latest.unwrap_or_else(|| Utc::now().naive_utc());

        let (start, end) = if let (Some(start), Some(end)) = (start, end) {
            match (
                DateTime::from_timestamp(start, 0),
                DateTime::from_timestamp(end, 0),
            ) {
                (Some(s), Some(e)) => (s.naive_utc(), e.naive_utc()),
                _ => {
                    return Err(Error::InvalidInput(format!(
                        "illegal time range provided({start}, {end})"
                    )))
                }
            }
        } else {
            (
                recent - chrono::TimeDelta::try_hours(2).expect("should be within the bound"),
                recent,
            )
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
                    let series = fill_vacant_time_slots(&series)?;

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
