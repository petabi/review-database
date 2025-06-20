use std::collections::HashSet;

use chrono::NaiveDateTime;
use column_description::dsl as col_d;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use num_traits::ToPrimitive;
use structured::{Element, FloatRange};

use super::{
    DEFAULT_NUMBER_OF_CLUSTER, DEFAULT_PORTION_OF_CLUSTER, DEFAULT_PORTION_OF_TOP_N,
    TopElementCountsByColumn, TopNOfMultipleCluster, ValueType, get_limited_cluster_ids,
    limited_top_n_of_clusters, to_element_counts, total_of_top_n,
};
use crate::{
    Database, Error,
    schema::{
        column_description, top_n_binary, top_n_datetime, top_n_enum, top_n_float, top_n_int,
        top_n_ipaddr, top_n_text,
    },
};

macro_rules! get_top_n_of_column {
    ($conn:expr, $top_d:ident, $top_table:ident, $value_type:ty, $c:expr, $i:expr, $tc:expr, $time:expr) => {{
        // First, get column descriptions for the clusters
        let column_descriptions = if let Some(time) = $time {
            col_d::column_description
                .select((col_d::id, col_d::cluster_id, col_d::column_index))
                .filter(
                    col_d::cluster_id
                        .eq_any($c)
                        .and(col_d::batch_ts.eq(time))
                        .and(col_d::column_index.eq($i)),
                )
                .load::<(i32, i32, i32)>($conn)
                .await?
        } else {
            col_d::column_description
                .select((col_d::id, col_d::cluster_id, col_d::column_index))
                .filter(col_d::cluster_id.eq_any($c).and(col_d::column_index.eq($i)))
                .load::<(i32, i32, i32)>($conn)
                .await?
        };

        let description_ids: Vec<i32> = column_descriptions.iter().map(|(id, _, _)| *id).collect();
        let desc_to_cluster: std::collections::HashMap<i32, i32> = column_descriptions
            .into_iter()
            .map(|(desc_id, cluster_id, _)| (desc_id, cluster_id))
            .collect();

        if !description_ids.is_empty() {
            // Then, get top_n data for those description IDs
            let top_n_data = $top_d::$top_table
                .select(($top_d::description_id, $top_d::value, $top_d::count))
                .filter($top_d::description_id.eq_any(&description_ids))
                .load::<(i32, $value_type, i64)>($conn)
                .await?;

            // Combine results in memory
            let mut top_n: Vec<TopNOfMultipleCluster> = top_n_data
                .into_iter()
                .filter_map(|(desc_id, value, count)| {
                    desc_to_cluster.get(&desc_id).map(|cluster_id| {
                        let value = ValueType::into_string(value);
                        TopNOfMultipleCluster {
                            cluster_id: *cluster_id,
                            column_index: $i,
                            _description_id: desc_id,
                            value,
                            count,
                        }
                    })
                })
                .collect();
            $tc.append(&mut top_n);
        }
    }};
}

pub(super) fn get_columns_for_top_n(
    store: &crate::Store,
    model_id: i32,
) -> Result<HashSet<i32>, Error> {
    let csv_column_extra_map = store.csv_column_extra_map();
    let Some(csv_extra) = csv_column_extra_map
        .get_by_model(model_id)
        .map_err(|e| Error::InvalidInput(format!("Failed to get csv column extra: {e}")))?
    else {
        return Ok(HashSet::new());
    };

    let Some(columns) = csv_extra.column_top_n else {
        return Ok(HashSet::new());
    };

    Ok(columns
        .into_iter()
        .enumerate()
        .filter_map(|(index, is)| {
            if is {
                Some(index.to_i32().expect("column index < i32::max"))
            } else {
                None
            }
        })
        .collect())
}

#[allow(clippy::type_complexity)]
async fn top_n_of_float(
    conn: &mut AsyncPgConnection,
    cluster_ids: &[i32],
    index: i32,
    time: Option<NaiveDateTime>,
) -> Result<Vec<(i32, i32, i32, f64, f64, i64)>, diesel::result::Error> {
    use top_n_float::dsl as top_d;

    // First, get column descriptions for the clusters
    let column_descriptions = if let Some(time) = time {
        col_d::column_description
            .select((col_d::id, col_d::cluster_id, col_d::column_index))
            .filter(
                col_d::cluster_id
                    .eq_any(cluster_ids)
                    .and(col_d::batch_ts.eq(time))
                    .and(col_d::column_index.eq(&index)),
            )
            .load::<(i32, i32, i32)>(conn)
            .await?
    } else {
        col_d::column_description
            .select((col_d::id, col_d::cluster_id, col_d::column_index))
            .filter(
                col_d::cluster_id
                    .eq_any(cluster_ids)
                    .and(col_d::column_index.eq(&index)),
            )
            .load::<(i32, i32, i32)>(conn)
            .await?
    };

    let description_ids: Vec<i32> = column_descriptions.iter().map(|(id, _, _)| *id).collect();
    let desc_to_cluster: std::collections::HashMap<i32, (i32, i32)> = column_descriptions
        .into_iter()
        .map(|(desc_id, cluster_id, column_index)| (desc_id, (cluster_id, column_index)))
        .collect();

    if description_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Then, get top_n_float data for those description IDs
    let top_n_data = top_d::top_n_float
        .select((
            top_d::description_id,
            top_d::value_smallest,
            top_d::value_largest,
            top_d::count,
        ))
        .filter(top_d::description_id.eq_any(&description_ids))
        .load::<(i32, f64, f64, i64)>(conn)
        .await?;

    // Combine results in memory
    let result = top_n_data
        .into_iter()
        .filter_map(|(desc_id, value_smallest, value_largest, count)| {
            desc_to_cluster
                .get(&desc_id)
                .map(|(cluster_id, column_index)| {
                    (
                        *cluster_id,
                        *column_index,
                        desc_id,
                        value_smallest,
                        value_largest,
                        count,
                    )
                })
        })
        .collect();

    Ok(result)
}

impl Database {
    /// Gets the top N columns of a model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    #[allow(clippy::too_many_lines)]
    pub async fn get_top_columns_of_model(
        &self,
        store: &crate::Store,
        model_id: i32,
        number_of_top_n: usize,
        time: Option<NaiveDateTime>,
        portion_of_clusters: Option<f64>,
        portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        let mut conn = self.pool.get().await?;
        let columns_for_top_n = get_columns_for_top_n(store, model_id)?;
        let mut column_types = self.get_column_types_of_model(model_id).await?;
        column_types.retain(|c| columns_for_top_n.contains(&c.column_index));

        let cluster_sizes = super::get_cluster_sizes(&mut conn, model_id).await?;
        let cluster_ids = get_limited_cluster_ids(
            &cluster_sizes,
            portion_of_clusters.unwrap_or(DEFAULT_PORTION_OF_CLUSTER),
            DEFAULT_NUMBER_OF_CLUSTER,
        );

        let mut top_n_of_cluster: Vec<TopNOfMultipleCluster> = Vec::new();

        for c in column_types {
            let index = c.column_index;
            match c.data_type.as_str() {
                "int64" => {
                    use top_n_int::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_int,
                        i64,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                "enum" => {
                    use top_n_enum::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_enum,
                        String,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                "float64" => {
                    let top_n = top_n_of_float(&mut conn, &cluster_ids, index, time).await?;
                    let mut top_n: Vec<TopNOfMultipleCluster> = top_n
                        .into_iter()
                        .map(|t| {
                            let value = Element::FloatRange(FloatRange {
                                smallest: t.3,
                                largest: t.4,
                            })
                            .to_string();
                            TopNOfMultipleCluster {
                                cluster_id: t.0,
                                column_index: t.1,
                                _description_id: t.2,
                                value,
                                count: t.5,
                            }
                        })
                        .collect();
                    top_n_of_cluster.append(&mut top_n);
                }
                "utf8" => {
                    use top_n_text::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_text,
                        String,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                "ipaddr" => {
                    use top_n_ipaddr::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_ipaddr,
                        String,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                "datetime" => {
                    use top_n_datetime::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_datetime,
                        NaiveDateTime,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                "binary" => {
                    use top_n_binary::dsl as top_d;
                    get_top_n_of_column!(
                        &mut conn,
                        top_d,
                        top_n_binary,
                        Vec<u8>,
                        &cluster_ids,
                        index,
                        top_n_of_cluster,
                        time
                    );
                }
                _ => unreachable!(),
            }
        }

        let top_n = total_of_top_n(top_n_of_cluster);
        let top_n =
            limited_top_n_of_clusters(top_n, portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N));
        Ok(to_element_counts(top_n, number_of_top_n))
    }
}
