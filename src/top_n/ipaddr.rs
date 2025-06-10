use std::{cmp::Reverse, collections::HashMap};

use chrono::NaiveDateTime;
use cluster::dsl as c_d;
use column_description::dsl as col_d;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use num_traits::ToPrimitive;
use top_n_ipaddr::dsl as top_d;

use super::{
    DEFAULT_NUMBER_OF_CLUSTER, DEFAULT_PORTION_OF_CLUSTER, DEFAULT_PORTION_OF_TOP_N, ElementCount,
    TopElementCountsByColumn, TopNOfCluster, TopNOfMultipleCluster, get_cluster_sizes,
    get_limited_cluster_ids, limited_top_n_of_clusters, to_element_counts, total_of_top_n,
};
use crate::{
    self as database, Database, Error,
    schema::{cluster, column_description, top_n_ipaddr},
};

async fn get_top_n_of_multiple_clusters(
    conn: &mut AsyncPgConnection,
    cluster_ids: &[i32],
    time: Option<NaiveDateTime>,
) -> Result<Vec<TopNOfMultipleCluster>, database::Error> {
    // First, get column descriptions for the specified clusters
    let column_descriptions = if let Some(time) = time {
        col_d::column_description
            .select((
                col_d::id,
                col_d::cluster_id,
                col_d::column_index,
                col_d::batch_ts,
            ))
            .filter(
                col_d::cluster_id
                    .eq_any(cluster_ids)
                    .and(col_d::batch_ts.eq(time)),
            )
            .load::<(i32, i32, i32, NaiveDateTime)>(conn)
            .await?
    } else {
        col_d::column_description
            .select((
                col_d::id,
                col_d::cluster_id,
                col_d::column_index,
                col_d::batch_ts,
            ))
            .filter(col_d::cluster_id.eq_any(cluster_ids))
            .load::<(i32, i32, i32, NaiveDateTime)>(conn)
            .await?
    };

    let description_ids: Vec<i32> = column_descriptions
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect();

    if description_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Then, get top_n_ipaddr data for those description IDs
    let top_n_data = top_d::top_n_ipaddr
        .select((top_d::description_id, top_d::value, top_d::count))
        .filter(top_d::description_id.eq_any(&description_ids))
        .load::<(i32, String, i64)>(conn)
        .await?;

    // Combine the results in memory
    let mut result = Vec::new();
    let description_map: std::collections::HashMap<i32, (i32, i32)> = column_descriptions
        .into_iter()
        .map(|(desc_id, cluster_id, column_index, _)| (desc_id, (cluster_id, column_index)))
        .collect();

    for (description_id, value, count) in top_n_data {
        if let Some((cluster_id, column_index)) = description_map.get(&description_id) {
            result.push(TopNOfMultipleCluster {
                cluster_id: *cluster_id,
                column_index: *column_index,
                _description_id: description_id,
                value,
                count,
            });
        }
    }

    Ok(result)
}

impl Database {
    /// Gets top N IP addresses of a cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn get_top_ip_addresses_of_cluster(
        &self,
        model_id: i32,
        cluster_id: &str,
        size: usize,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        let mut conn = self.pool.get().await?;

        // First, get clusters for the model and cluster_id
        let clusters = c_d::cluster
            .select((c_d::id, c_d::cluster_id))
            .filter(
                c_d::model_id
                    .eq(model_id)
                    .and(c_d::cluster_id.eq(cluster_id)),
            )
            .load::<(i32, String)>(&mut conn)
            .await?;

        if clusters.is_empty() {
            return Ok(Vec::new());
        }

        let cluster_ids: Vec<i32> = clusters.iter().map(|(id, _)| *id).collect();

        // Then, get column descriptions for these clusters
        let column_descriptions = col_d::column_description
            .select((col_d::id, col_d::cluster_id, col_d::column_index))
            .filter(col_d::cluster_id.eq_any(&cluster_ids))
            .load::<(i32, i32, i32)>(&mut conn)
            .await?;

        let description_ids: Vec<i32> = column_descriptions.iter().map(|(id, _, _)| *id).collect();

        if description_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Finally, get top_n_ipaddr data for those description IDs
        let top_n_data = top_d::top_n_ipaddr
            .select((top_d::description_id, top_d::value, top_d::count))
            .filter(top_d::description_id.eq_any(&description_ids))
            .load::<(i32, String, i64)>(&mut conn)
            .await?;

        // Combine results in memory
        let description_map: std::collections::HashMap<i32, i32> = column_descriptions
            .into_iter()
            .map(|(desc_id, _, column_index)| (desc_id, column_index))
            .collect();

        let mut values = Vec::new();
        for (description_id, value, count) in top_n_data {
            if let Some(column_index) = description_map.get(&description_id) {
                values.push(TopNOfCluster {
                    column_index: *column_index,
                    _description_id: description_id,
                    value,
                    count,
                });
            }
        }

        let mut top_n: HashMap<usize, HashMap<String, i64>> = HashMap::new(); // String: Ip Address
        for v in values {
            if let (Some(column_index), value, count) =
                (v.column_index.to_usize(), v.value, v.count)
            {
                *top_n
                    .entry(column_index)
                    .or_default()
                    .entry(value)
                    .or_insert(0) += count;
            }
        }

        let mut top_n: Vec<TopElementCountsByColumn> = top_n
            .into_iter()
            .map(|t| {
                let mut top_n: Vec<ElementCount> =
                    t.1.into_iter()
                        .map(|t| ElementCount {
                            value: t.0,
                            count: t.1,
                        })
                        .collect();
                top_n.sort_by_key(|v| Reverse(v.count));
                top_n.truncate(size);
                TopElementCountsByColumn {
                    column_index: t.0,
                    counts: top_n,
                }
            })
            .collect();
        top_n.sort_by_key(|v| v.column_index);
        Ok(top_n)
    }

    /// Gets top N IP addresses of a model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn get_top_ip_addresses_of_model(
        &self,
        model_id: i32,
        size: usize,
        time: Option<NaiveDateTime>,
        portion_of_clusters: Option<f64>,
        portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        let mut conn = self.pool.get().await?;
        let cluster_sizes = get_cluster_sizes(&mut conn, model_id).await?;
        let cluster_ids = get_limited_cluster_ids(
            &cluster_sizes,
            portion_of_clusters.unwrap_or(DEFAULT_PORTION_OF_CLUSTER),
            DEFAULT_NUMBER_OF_CLUSTER,
        );

        let top_n = get_top_n_of_multiple_clusters(&mut conn, &cluster_ids, time).await?;
        let top_n = total_of_top_n(top_n);
        let top_n =
            limited_top_n_of_clusters(top_n, portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N));
        Ok(to_element_counts(top_n, size))
    }
}
