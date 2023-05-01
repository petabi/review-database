use crate::{
    self as database,
    schema::{cluster, time_series},
    Database, Error, TimeCount,
};
use chrono::{Duration, NaiveDateTime, Utc};
use diesel::{dsl::max, BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl};
use diesel_async::{pg::AsyncPgConnection, RunQueryDsl};
use num_traits::ToPrimitive;
use serde::Deserialize;
use std::collections::HashMap;

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

#[derive(Clone, Deserialize)]
pub struct LineSegment {
    pub first_index: usize,
    pub last_index: usize,
    pub reg_original: Regression,
    pub reg_trend: Regression,
}

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
        let mut conn = self.pool.get_diesel_conn().await?;
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
                .or_insert_with(HashMap::<String, HashMap<NaiveDateTime, i64>>::new)
                .entry(v.cluster_id)
                .or_insert_with(HashMap::<NaiveDateTime, i64>::new)
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
                            series.sort_by(|a, b| a.time.cmp(&b.time));
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
            s.trends.sort_by(|a, b| b.series.len().cmp(&a.series.len())); // for fixed order
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
    let series = if let Some(time) = time {
        c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select((c_d::cluster_id, t_d::count_index, t_d::value, t_d::count))
            .filter(c_d::model_id.eq(model_id).and(t_d::time.eq(time)))
            .load::<TimeSeriesLoadByCluster>(conn)
            .await?
    } else {
        let latest = c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select(max(t_d::value))
            .filter(c_d::model_id.eq(model_id))
            .first::<Option<NaiveDateTime>>(conn)
            .await?;

        let recent = latest.unwrap_or_else(|| Utc::now().naive_utc());
        let (start, end) = if let (Some(start), Some(end)) = (start, end) {
            match (
                NaiveDateTime::from_timestamp_opt(start, 0),
                NaiveDateTime::from_timestamp_opt(end, 0),
            ) {
                (Some(s), Some(e)) => (s, e),
                _ => {
                    return Err(database::Error::InvalidInput(format!(
                        "illegal time range provided ({start},{end})"
                    )))
                }
            }
        } else {
            (recent - Duration::hours(2), recent)
        };

        c_d::cluster
            .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
            .select((c_d::cluster_id, t_d::count_index, t_d::value, t_d::count))
            .filter(
                c_d::model_id
                    .eq(model_id)
                    .and(t_d::value.gt(start)) // HIGHLIGHT: first and last items should not be included because they might have insufficient counts.
                    .and(t_d::value.lt(end)),
            )
            .load::<TimeSeriesLoadByCluster>(conn)
            .await?
    };

    Ok(series)
}
