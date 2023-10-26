use crate::{
    csv_indicator::get_csv_indicators,
    schema::{
        cluster, column_description, model, top_n_binary, top_n_datetime, top_n_enum, top_n_int,
        top_n_ipaddr, top_n_text,
    },
    Database, Error, StructuredColumnType,
};
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl};
use diesel_async::RunQueryDsl;
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use structured::Element;

use cluster::dsl as c_d;
use column_description::dsl as cd_d;
use model::dsl as m_d;

// As structured::ElementCount has count as usize, redefine this here.
#[derive(Debug)]
struct ElementCount {
    value: Element,
    count: i64,
}

macro_rules! pass_value {
    ($value:expr) => {{
        $value
    }};
}

macro_rules! pass_value_ip {
    ($value:expr) => {{
        IpAddr::V4(
            Ipv4Addr::from_str($value.as_str()).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0)),
        )
    }};
}

macro_rules! load_top_n {
    ($top_n:ident, $value:ty, $model_id:expr, $time:expr, $conn:expr, $output:expr, $elem:expr, $value_func:tt) => {{
        use $top_n::dsl as t_d;
        let top_n: Vec<(i32, String, $value, i64)> = if let Some(time) = $time {
            t_d::$top_n
                .inner_join(cd_d::column_description.on(t_d::description_id.eq(cd_d::id)))
                .inner_join(c_d::cluster.on(cd_d::cluster_id.eq(c_d::id)))
                .inner_join(m_d::model.on(c_d::model_id.eq(m_d::id)))
                .select((c_d::id, c_d::cluster_id, t_d::value, t_d::count))
                .filter(m_d::id.eq($model_id).and(cd_d::batch_ts.eq(time)))
                .load::<(i32, String, $value, i64)>($conn)
                .await?
        } else {
            t_d::$top_n
                .inner_join(cd_d::column_description.on(t_d::description_id.eq(cd_d::id)))
                .inner_join(c_d::cluster.on(cd_d::cluster_id.eq(c_d::id)))
                .inner_join(m_d::model.on(c_d::model_id.eq(m_d::id)))
                .select((c_d::id, c_d::cluster_id, t_d::value, t_d::count))
                .filter(m_d::id.eq($model_id))
                .load::<(i32, String, $value, i64)>($conn)
                .await?
        };

        if top_n.is_empty() {
            continue;
        }

        for (cluster_id, cluster_name, value, count) in top_n {
            $output
                .entry((cluster_id, cluster_name))
                .or_insert_with(Vec::<ElementCount>::new)
                .push(ElementCount {
                    value: $elem($value_func!(value)),
                    count,
                })
        }
    }};
}

#[allow(clippy::module_name_repetitions)]
pub struct ClusterScore {
    pub cluster_id: i32,
    pub cluster_name: String,
    pub score: f64,
}

pub struct ClusterScoreSet {
    pub top_n_sum: Vec<ClusterScore>,
    pub top_n_rate: Vec<ClusterScore>,
}

impl Database {
    /// Gets top N clusters by score.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn get_top_clusters_by_score(
        &self,
        model_id: i32,
        size: usize,
        time: Option<NaiveDateTime>,
        column_types: &[StructuredColumnType],
    ) -> Result<ClusterScoreSet, Error> {
        let columns_indices: Vec<usize> = column_types
            .iter()
            .map(|c| {
                c.column_index
                    .to_usize()
                    .expect("safe: positive i32 -> usize")
            })
            .collect();

        let mut conn = self.pool.get_diesel_conn().await?;
        let indicators: HashMap<usize, String> =
            get_csv_indicators(&mut conn, model_id, &columns_indices).await?;
        let mut indicator_indices: Vec<usize> = indicators.keys().copied().collect();
        indicator_indices.sort_unstable();

        let mut scores_sum: HashMap<(i32, String), f64> = HashMap::new();
        let mut scores_rate: HashMap<(i32, String), f64> = HashMap::new();
        for column_index in indicator_indices {
            let column_type: &str = &column_types[column_index].data_type;
            let Some(indicator) = indicators
                .get(&column_index)
                .and_then(|indi| serde_json::from_str::<HashMap<String, f64>>(indi).ok())
            else {
                continue;
            };

            let mut top_n_by_cluster: HashMap<(i32, String), Vec<ElementCount>> = HashMap::new(); // i32, String = id, cluster_id
            match column_type {
                "int64" => {
                    load_top_n!(
                        top_n_int,
                        i64,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::Int,
                        pass_value
                    );
                }
                "enum" => {
                    load_top_n!(
                        top_n_enum,
                        String,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::Enum,
                        pass_value
                    );
                }
                "float64" => {
                    // TODO: implement later or not?
                    continue;
                }
                "utf8" => {
                    load_top_n!(
                        top_n_text,
                        String,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::Text,
                        pass_value
                    );
                }
                "ipaddr" => {
                    load_top_n!(
                        top_n_ipaddr,
                        String,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::IpAddr,
                        pass_value_ip
                    );
                }
                "datetime" => {
                    load_top_n!(
                        top_n_datetime,
                        NaiveDateTime,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::DateTime,
                        pass_value
                    );
                }
                "binary" => {
                    load_top_n!(
                        top_n_binary,
                        Vec<u8>,
                        model_id,
                        time,
                        &mut conn,
                        top_n_by_cluster,
                        Element::Binary,
                        pass_value
                    );
                }
                _ => unreachable!(),
            }

            for ((cluster_id, cluster_name), top_n) in top_n_by_cluster {
                let mut score: f64 = 0_f64;
                let mut count_sum: f64 = 0_f64;
                for e in top_n {
                    let weight: f64 = indicator.get(&e.value.to_string()).map_or(0_f64, |w| *w);
                    let count = e.count.to_f64().expect("safe: usize -> f64");
                    score += count * weight;
                    count_sum += count;
                }
                if score > 0_f64 {
                    *scores_sum
                        .entry((cluster_id, cluster_name.clone()))
                        .or_insert(0_f64) += score;
                    *scores_rate
                        .entry((cluster_id, cluster_name))
                        .or_insert(0_f64) += score / count_sum;
                }
            }
        }

        let mut scores_sum: Vec<ClusterScore> = scores_sum
            .into_iter()
            .map(|((cluster_id, cluster_name), score)| ClusterScore {
                cluster_id,
                cluster_name,
                score,
            })
            .collect();

        scores_sum.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));
        scores_sum.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut scores_rate: Vec<ClusterScore> = scores_rate
            .into_iter()
            .map(|((cluster_id, cluster_name), score)| ClusterScore {
                cluster_id,
                cluster_name,
                score,
            })
            .collect();

        scores_rate.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));
        scores_rate.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        scores_sum.truncate(size);
        scores_rate.truncate(size);
        Ok(ClusterScoreSet {
            top_n_sum: scores_sum,
            top_n_rate: scores_rate,
        })
    }
}
