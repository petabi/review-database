#![allow(deprecated)] // TODO: Remove this when LineSegment and Regression structs are deleted

use std::{cmp::Reverse, collections::HashMap};

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, dsl::max};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use num_traits::ToPrimitive;
use serde::Deserialize;

use crate::{
    self as database, Database, Error, TimeCount,
    schema::{cluster, time_series},
};

#[derive(Debug, Queryable)]
struct TimeSeriesLoadByCluster {
    cluster_id: String,
    count_index: Option<i32>,
    value: NaiveDateTime,
    count: i64,
}

#[derive(Deserialize)]
pub struct TopTrendsByColumn {
    pub count_index: usize, // 100_000 means counting events themselves.
    pub trends: Vec<ClusterTrend>,
}

#[derive(Clone, Deserialize)]
pub struct ClusterTrend {
    pub cluster_id: String,
    pub series: Vec<TimeCount>,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Clone, Deserialize)]
pub struct LineSegment {
    pub first_index: usize,
    pub last_index: usize,
    pub reg_original: Regression,
    pub reg_trend: Regression,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Clone, Deserialize)]
pub struct Regression {
    pub slope: f64,
    pub intercept: f64,
    pub r_square: f64,
}

use cluster::dsl as c_d;
use time_series::dsl as t_d;

impl Database {
    /// Returns the top trends of a model.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn get_top_time_series_of_model(
        &self,
        model_id: i32,
        time: Option<NaiveDateTime>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Vec<TopTrendsByColumn>, Error> {
        let mut conn = self.pool.get().await?;
        let values = get_time_series_of_clusters(&mut conn, model_id, time, start, end).await?;

        let mut series: HashMap<usize, HashMap<String, HashMap<NaiveDateTime, i64>>> =
            HashMap::new();
        for v in values {
            let (count_index, value, count) = (
                v.count_index
                    .map_or(100_000, |i| i.to_usize().expect("safe: positive")),
                // 100_000 means counting events themselves, not any other column values.
                v.value,
                v.count,
            );
            *series
                .entry(count_index)
                .or_default()
                .entry(v.cluster_id)
                .or_default()
                .entry(value)
                .or_insert(0) += count;
        }

        let mut series: Vec<TopTrendsByColumn> = series
            .into_iter()
            .map(|(count_index, cluster_series)| TopTrendsByColumn {
                count_index,
                trends: cluster_series
                    .into_iter()
                    .filter_map(|(cluster_id, series)| {
                        if series.is_empty() {
                            None
                        } else {
                            let mut series: Vec<TimeCount> = series
                                .into_iter()
                                .map(|(time, count)| TimeCount {
                                    time,
                                    count: count.to_usize().unwrap_or(usize::MAX),
                                })
                                .collect();
                            series.sort_by_key(|v| v.time);
                            if time.is_some() && series.len() > 2 {
                                series.pop();
                                series.remove(0);
                            }

                            Some(ClusterTrend { cluster_id, series })
                        }
                    })
                    .collect(),
            })
            .collect();

        for s in &mut series {
            s.trends.sort_by_key(|v| Reverse(v.series.len())); // for fixed order
        }
        Ok(series)
    }
}

async fn get_time_series_of_clusters(
    conn: &mut AsyncPgConnection,
    model_id: i32,
    time: Option<NaiveDateTime>,
    start: Option<i64>,
    end: Option<i64>,
) -> Result<Vec<TimeSeriesLoadByCluster>, database::Error> {
    // First, get clusters for the model
    let clusters = c_d::cluster
        .select((c_d::id, c_d::cluster_id))
        .filter(c_d::model_id.eq(model_id))
        .load::<(i32, String)>(conn)
        .await?;

    let cluster_db_ids: Vec<i32> = clusters.iter().map(|(id, _)| *id).collect();
    let cluster_id_map: std::collections::HashMap<i32, String> = clusters.into_iter().collect();

    if cluster_db_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Then, get time series data for those clusters
    let time_series_data = if let Some(time) = time {
        t_d::time_series
            .select((t_d::cluster_id, t_d::count_index, t_d::value, t_d::count))
            .filter(
                t_d::cluster_id
                    .eq_any(&cluster_db_ids)
                    .and(t_d::time.eq(time)),
            )
            .load::<(i32, Option<i32>, NaiveDateTime, i64)>(conn)
            .await?
    } else {
        let latest = t_d::time_series
            .select(max(t_d::value))
            .filter(t_d::cluster_id.eq_any(&cluster_db_ids))
            .first::<Option<NaiveDateTime>>(conn)
            .await?;

        let recent = latest.unwrap_or_else(|| Utc::now().naive_utc());
        let (start, end) = if let (Some(start), Some(end)) = (start, end) {
            match (
                chrono::DateTime::from_timestamp(start, 0),
                chrono::DateTime::from_timestamp(end, 0),
            ) {
                (Some(s), Some(e)) => (s.naive_utc(), e.naive_utc()),
                _ => {
                    return Err(database::Error::InvalidInput(format!(
                        "illegal time range provided ({start},{end})"
                    )));
                }
            }
        } else {
            (
                recent - TimeDelta::try_hours(2).expect("should be within the limit"),
                recent,
            )
        };

        t_d::time_series
            .select((t_d::cluster_id, t_d::count_index, t_d::value, t_d::count))
            .filter(
                t_d::cluster_id
                    .eq_any(&cluster_db_ids)
                    .and(t_d::value.gt(start)) // HIGHLIGHT: first and last items should not be included because they might have insufficient counts.
                    .and(t_d::value.lt(end)),
            )
            .load::<(i32, Option<i32>, NaiveDateTime, i64)>(conn)
            .await?
    };

    // Combine results in memory
    let result = time_series_data
        .into_iter()
        .filter_map(|(cluster_db_id, count_index, value, count)| {
            cluster_id_map
                .get(&cluster_db_id)
                .map(|cluster_id| TimeSeriesLoadByCluster {
                    cluster_id: cluster_id.clone(),
                    count_index,
                    value,
                    count,
                })
        })
        .collect();

    Ok(result)
}
