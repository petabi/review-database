use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, QueryDsl,
    sql_types::{BigInt, Integer, Text, Timestamp},
};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use structured::{Element, FloatRange};

use super::{ElementCount, StructuredColumnType, TopElementCountsByColumn};
use crate::{
    self as database, Database, Error,
    schema::{
        cluster, column_description, top_n_binary, top_n_datetime, top_n_enum, top_n_float,
        top_n_int, top_n_ipaddr, top_n_text,
    },
};

#[derive(Debug, QueryableByName, Serialize)]
pub struct SelectedCluster {
    #[diesel(sql_type = Integer)]
    model_id: i32,
    #[diesel(sql_type = Integer)]
    column_index: i32,
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = Timestamp)]
    batch_ts: NaiveDateTime,
    #[diesel(sql_type = Integer)]
    description_id: i32,
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(Deserialize)]
pub struct TopColumnsOfCluster {
    pub cluster_id: String,
    pub columns: Vec<TopElementCountsByColumn>,
}

#[derive(Deserialize)]
pub struct TopMultimaps {
    pub n_index: usize,
    pub selected: Vec<TopColumnsOfCluster>,
}

use cluster::dsl as c_d;
use column_description::dsl as cd_d;

macro_rules! get_top_n_of_column_by_round {
    ($conn:expr, $top_d:ident, $top_table:ident, $load_type:ty, $d:expr, $c:expr, $b_ts:expr, $index:expr, $func:tt, $top_n:expr) => {{
        // First, get clusters for the model
        let clusters = c_d::cluster
            .select((c_d::id, c_d::cluster_id))
            .filter(c_d::model_id.eq($d).and(c_d::cluster_id.eq_any($c)))
            .load::<(i32, String)>($conn)
            .await?;

        let cluster_db_ids: Vec<i32> = clusters.iter().map(|(id, _)| *id).collect();
        let cluster_id_map: std::collections::HashMap<i32, String> = clusters.into_iter().collect();

        if cluster_db_ids.is_empty() {
            $top_n = Ok(std::collections::HashMap::new());
        } else {
            // Then, get column descriptions
            let column_descriptions = cd_d::column_description
                .select((cd_d::id, cd_d::cluster_id, cd_d::batch_ts))
                .filter(
                    cd_d::cluster_id
                        .eq_any(&cluster_db_ids)
                        .and(cd_d::batch_ts.eq_any($b_ts))
                        .and(cd_d::column_index.eq($index)),
                )
                .load::<(i32, i32, NaiveDateTime)>($conn)
                .await?;

            let description_ids: Vec<i32> =
                column_descriptions.iter().map(|(id, _, _)| *id).collect();
            let desc_to_cluster: std::collections::HashMap<i32, String> = column_descriptions
                .into_iter()
                .filter_map(|(desc_id, cluster_db_id, _batch_ts)| {
                    cluster_id_map
                        .get(&cluster_db_id)
                        .map(|cluster_id| (desc_id, cluster_id.clone()))
                })
                .collect();

            if description_ids.is_empty() {
                $top_n = Ok(std::collections::HashMap::new());
            } else {
                // Finally, get top_n data
                let top_n_data = $top_d::$top_table
                    .select(($top_d::description_id, $top_d::value, $top_d::count))
                    .filter($top_d::description_id.eq_any(&description_ids))
                    .load::<(i32, $load_type, i64)>($conn)
                    .await?;

                let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
                for (description_id, raw_value, count) in &top_n_data {
                    if let Some(cluster_id) = desc_to_cluster.get(description_id) {
                        let value;
                        $func!(value, raw_value);

                        top_n_by_cluster
                            .entry(cluster_id.clone())
                            .or_insert_with(Vec::<ElementCount>::new)
                            .push(ElementCount {
                                value,
                                count: *count,
                            });
                    }
                }

                for (_, top_n) in top_n_by_cluster.iter_mut() {
                    top_n.sort_by(|a, b| a.value.cmp(&b.value));
                    top_n.sort_by(|a, b| b.count.cmp(&a.count));
                }

                $top_n = Ok(top_n_by_cluster);
            }
        }
    }};
}

macro_rules! get_value_of_top_n_round_by_to_string {
    ($value_to:expr, $value_from:expr) => {{
        $value_to = $value_from.to_string();
    }};
}

macro_rules! get_value_of_top_n_round_by_clone {
    ($value_to:expr, $value_from:expr) => {{
        $value_to = $value_from.clone();
    }};
}

macro_rules! get_value_of_top_n_round_by_utf8 {
    ($value_to:expr, $value_from:expr) => {{
        $value_to = String::from_utf8_lossy($value_from).to_string();
    }};
}

#[allow(clippy::too_many_lines)]
async fn get_top_n(
    conn: &mut AsyncPgConnection,
    model_id: i32,
    cluster_ids: &[String],
    batch_ts: &[NaiveDateTime],
    column_index: i32,
    column_type: &str,
) -> Result<HashMap<String, Vec<ElementCount>>, database::Error> {
    match column_type {
        "int64" => {
            use top_n_int::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_int,
                i64,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_to_string,
                top_n
            );
            top_n
        }
        "enum" => {
            use top_n_enum::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_enum,
                String,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "float64" => {
            use top_n_float::dsl as ti_d;

            // Get clusters for the model
            let clusters = c_d::cluster
                .select((c_d::id, c_d::cluster_id))
                .filter(
                    c_d::model_id
                        .eq(model_id)
                        .and(c_d::cluster_id.eq_any(cluster_ids)),
                )
                .load::<(i32, String)>(conn)
                .await?;

            let cluster_db_ids: Vec<i32> = clusters.iter().map(|(id, _)| *id).collect();
            let cluster_id_map: std::collections::HashMap<i32, String> =
                clusters.into_iter().collect();

            if cluster_db_ids.is_empty() {
                return Ok(std::collections::HashMap::new());
            }

            // Get column descriptions
            let column_descriptions = cd_d::column_description
                .select((cd_d::id, cd_d::cluster_id, cd_d::batch_ts))
                .filter(
                    cd_d::cluster_id
                        .eq_any(&cluster_db_ids)
                        .and(cd_d::batch_ts.eq_any(batch_ts))
                        .and(cd_d::column_index.eq(&column_index)),
                )
                .load::<(i32, i32, NaiveDateTime)>(conn)
                .await?;

            let description_ids: Vec<i32> =
                column_descriptions.iter().map(|(id, _, _)| *id).collect();
            let desc_to_cluster: std::collections::HashMap<i32, String> = column_descriptions
                .into_iter()
                .filter_map(|(desc_id, cluster_db_id, _batch_ts)| {
                    cluster_id_map
                        .get(&cluster_db_id)
                        .map(|cluster_id| (desc_id, cluster_id.clone()))
                })
                .collect();

            if description_ids.is_empty() {
                return Ok(std::collections::HashMap::new());
            }

            // Get top_n_float data
            let top_n = ti_d::top_n_float
                .select((
                    ti_d::description_id,
                    ti_d::value_smallest,
                    ti_d::value_largest,
                    ti_d::count,
                ))
                .filter(ti_d::description_id.eq_any(&description_ids))
                .load::<(i32, f64, f64, i64)>(conn)
                .await?;

            let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
            for (description_id, value_smallest, value_largest, count) in &top_n {
                if let Some(cluster_id) = desc_to_cluster.get(description_id) {
                    let smallest = *value_smallest;
                    let largest = *value_largest;

                    top_n_by_cluster
                        .entry(cluster_id.clone())
                        .or_default()
                        .push(ElementCount {
                            value: Element::FloatRange(FloatRange { smallest, largest })
                                .to_string(),
                            count: *count,
                        });
                }
            }

            for top_n in top_n_by_cluster.values_mut() {
                top_n.sort_by(|a, b| a.value.cmp(&b.value));
                top_n.sort_by(|a, b| b.count.cmp(&a.count));
            }

            Ok(top_n_by_cluster)
        }
        "utf8" => {
            use top_n_text::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_text,
                String,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "ipaddr" => {
            use top_n_ipaddr::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_ipaddr,
                String,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "datetime" => {
            use top_n_datetime::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_datetime,
                NaiveDateTime,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_to_string,
                top_n
            );
            top_n
        }
        "binary" => {
            use top_n_binary::dsl as ti_d;
            let top_n;
            get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_binary,
                Vec<u8>,
                model_id,
                cluster_ids,
                batch_ts,
                &column_index,
                get_value_of_top_n_round_by_utf8,
                top_n
            );
            top_n
        }
        _ => unreachable!(),
    }
}

impl Database {
    /// Gets the top N multimaps of a model.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_possible_truncation)]
    pub async fn get_top_multimaps_of_model(
        &self,
        store: &crate::Store,
        model_id: i32,
        number_of_top_n: usize,
        min_top_n_of_1_to_n: usize,
        time: Option<NaiveDateTime>,
        column_types: Vec<StructuredColumnType>,
    ) -> Result<Vec<TopMultimaps>, Error> {
        let mut conn = self.pool.get().await?;
        let column_types: HashMap<usize, String> = column_types
            .into_iter()
            .map(|c| (c.column_index.to_usize().expect("safe"), c.data_type))
            .collect();

        let csv_column_extra_map = store.csv_column_extra_map();
        let csv_extra = csv_column_extra_map
            .get_by_model(model_id)
            .map_err(|e| Error::InvalidInput(format!("Failed to get csv column extra: {e}")))?;

        let columns_for_1_to_n = if let Some(csv_extra) = csv_extra {
            (csv_extra.column_1, csv_extra.column_n)
        } else {
            (None, None)
        };

        let columns_for_1: Vec<usize> = columns_for_1_to_n.0.map_or_else(Vec::new, |c| {
            c.iter()
                .enumerate()
                .filter_map(|(index, is)| if *is { Some(index) } else { None })
                .collect()
        });

        let columns_for_n: Vec<usize> = columns_for_1_to_n.1.map_or_else(Vec::new, |c| {
            c.iter()
                .enumerate()
                .filter_map(|(index, is)| if *is { Some(index) } else { None })
                .collect()
        });

        let mut top_n_transfer: Vec<TopMultimaps> = Vec::new();
        for column_n in &columns_for_n {
            let column_type: &str = if let Some(column_type) = column_types.get(column_n) {
                column_type
            } else {
                return Ok(Vec::<TopMultimaps>::new());
            };
            let _top_table = match column_type {
                "int64" => "top_n_int",
                "enum" => "top_n_enum",
                "float64" => "top_n_float",
                "utf8" => "top_n_text",
                "ipaddr" => "top_n_ipaddr",
                "datetime" => "top_n_datetime",
                "binary" => "top_n_binary",
                _ => unreachable!(),
            };

            // Instead of complex SQL JOIN, break it down into separate queries

            // 1. Get clusters for the model (excluding category_id = 2)
            let clusters = c_d::cluster
                .select((c_d::id, c_d::cluster_id, c_d::model_id, c_d::category_id))
                .filter(c_d::model_id.eq(model_id).and(c_d::category_id.ne(2)))
                .load::<(i32, String, i32, i32)>(&mut conn)
                .await?;

            let cluster_db_ids: Vec<i32> = clusters.iter().map(|(id, _, _, _)| *id).collect();
            let cluster_info: std::collections::HashMap<i32, String> = clusters
                .into_iter()
                .map(|(id, cluster_id, _, _)| (id, cluster_id))
                .collect();

            if cluster_db_ids.is_empty() {
                continue;
            }

            // 2. Get column descriptions for these clusters
            let column_descriptions =
                if let Some(time) = time {
                    cd_d::column_description
                        .select((
                            cd_d::id,
                            cd_d::cluster_id,
                            cd_d::column_index,
                            cd_d::batch_ts,
                        ))
                        .filter(
                            cd_d::cluster_id
                                .eq_any(&cluster_db_ids)
                                .and(cd_d::column_index.eq(i32::try_from(*column_n).map_err(
                                    |_| Error::InvalidInput("column index too large".to_string()),
                                )?))
                                .and(cd_d::batch_ts.eq(time)),
                        )
                        .load::<(i32, i32, i32, NaiveDateTime)>(&mut conn)
                        .await?
                } else {
                    cd_d::column_description
                        .select((
                            cd_d::id,
                            cd_d::cluster_id,
                            cd_d::column_index,
                            cd_d::batch_ts,
                        ))
                        .filter(cd_d::cluster_id.eq_any(&cluster_db_ids).and(
                            cd_d::column_index.eq(i32::try_from(*column_n).map_err(|_| {
                                Error::InvalidInput("column index too large".to_string())
                            })?),
                        ))
                        .load::<(i32, i32, i32, NaiveDateTime)>(&mut conn)
                        .await?
                };

            let description_ids: Vec<i32> = column_descriptions
                .iter()
                .map(|(id, _, _, _)| *id)
                .collect();

            if description_ids.is_empty() {
                continue;
            }

            // 3. Count top_n entries per description_id using the appropriate table
            let top_n_counts = match column_type {
                "int64" => {
                    use top_n_int::dsl as top_d;
                    let raw_data = top_d::top_n_int
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "enum" => {
                    use top_n_enum::dsl as top_d;
                    let raw_data = top_d::top_n_enum
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "float64" => {
                    use top_n_float::dsl as top_d;
                    let raw_data = top_d::top_n_float
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "utf8" => {
                    use top_n_text::dsl as top_d;
                    let raw_data = top_d::top_n_text
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "ipaddr" => {
                    use top_n_ipaddr::dsl as top_d;
                    let raw_data = top_d::top_n_ipaddr
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "datetime" => {
                    use top_n_datetime::dsl as top_d;
                    let raw_data = top_d::top_n_datetime
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                "binary" => {
                    use top_n_binary::dsl as top_d;
                    let raw_data = top_d::top_n_binary
                        .select((top_d::description_id, top_d::id))
                        .filter(top_d::description_id.eq_any(&description_ids))
                        .load::<(i32, i32)>(&mut conn)
                        .await?;

                    let mut counts: HashMap<i32, i64> = HashMap::new();
                    for (desc_id, _) in raw_data {
                        *counts.entry(desc_id).or_insert(0) += 1;
                    }
                    counts
                        .into_iter()
                        .filter(|(_, count)| *count > min_top_n_of_1_to_n as i64)
                        .collect::<Vec<(i32, i64)>>()
                }
                _ => unreachable!(),
            };

            // 4. Build SelectedCluster results by combining the data in memory
            let desc_count_map: std::collections::HashMap<i32, i64> =
                top_n_counts.into_iter().collect();
            let desc_info_map: std::collections::HashMap<i32, (i32, NaiveDateTime)> =
                column_descriptions
                    .into_iter()
                    .map(|(desc_id, cluster_db_id, _, batch_ts)| {
                        (desc_id, (cluster_db_id, batch_ts))
                    })
                    .collect();

            let mut selected_clusters = Vec::new();
            for (description_id, count) in &desc_count_map {
                if let Some((cluster_db_id, batch_ts)) = desc_info_map.get(description_id) {
                    if let Some(cluster_id) = cluster_info.get(cluster_db_id) {
                        selected_clusters.push(SelectedCluster {
                            model_id,
                            column_index: *column_n as i32,
                            cluster_id: cluster_id.clone(),
                            batch_ts: *batch_ts,
                            description_id: *description_id,
                            count: *count,
                        });
                    }
                }
            }

            // Sort by count descending (equivalent to ORDER BY COUNT(top.id) DESC)
            selected_clusters.sort_by(|a, b| b.count.cmp(&a.count));

            let mut sorted_clusters: HashMap<String, Vec<(NaiveDateTime, i64)>> = HashMap::new();
            for cluster in selected_clusters {
                sorted_clusters
                    .entry(cluster.cluster_id)
                    .or_default()
                    .push((cluster.batch_ts, cluster.count));
            }
            for top_n in sorted_clusters.values_mut() {
                top_n.sort_by(|a, b| b.0.cmp(&a.0)); // recent one among rounds is more important. (assuming recent event id is bigger)
                top_n.sort_by(|a, b| b.1.cmp(&a.1));
            }

            let mut sorted_clusters: Vec<(String, NaiveDateTime, i64)> =
                sorted_clusters // cluster_id, batch_ts, count
                    .into_iter()
                    .map(|(cluster_id, top_n)| (cluster_id, top_n[0].0, top_n[0].1))
                    .collect();
            // HIGHLIGHT: take the biggest round only in each cluster
            sorted_clusters.sort_by(|a, b| a.0.cmp(&b.0)); // first, sort clusters by alphabetical order
            sorted_clusters.sort_by(|a, b| b.2.cmp(&a.2)); // then, sort by count
            sorted_clusters.truncate(number_of_top_n);

            let cluster_ids: Vec<String> = sorted_clusters.iter().map(|c| c.0.clone()).collect();
            let batch_ts: Vec<NaiveDateTime> = sorted_clusters.iter().map(|c| c.1).collect();

            let mut top_n_of_clusters: HashMap<String, Vec<TopElementCountsByColumn>> =
                HashMap::new();
            for column_1 in &columns_for_1 {
                let column_type: &str = if let Some(column_type) = column_types.get(column_1) {
                    column_type
                } else {
                    return Ok(Vec::<TopMultimaps>::new());
                };
                let column_index: i32 = if let Some(column_index) = column_1.to_i32() {
                    column_index
                } else {
                    return Ok(Vec::<TopMultimaps>::new());
                };
                let top_n = get_top_n(
                    &mut conn,
                    model_id,
                    &cluster_ids,
                    &batch_ts,
                    column_index,
                    column_type,
                )
                .await?;
                for (cluster_id, top_n) in top_n {
                    top_n_of_clusters.entry(cluster_id).or_default().push(
                        TopElementCountsByColumn {
                            column_index: *column_1,
                            counts: top_n,
                        },
                    );
                }
            }

            for column_n in &columns_for_n {
                let column_type: &str = if let Some(column_type) = column_types.get(column_n) {
                    column_type
                } else {
                    return Ok(Vec::<TopMultimaps>::new());
                };
                let column_index: i32 = if let Some(column_index) = column_n.to_i32() {
                    column_index
                } else {
                    return Ok(Vec::<TopMultimaps>::new());
                };
                let top_n = get_top_n(
                    &mut conn,
                    model_id,
                    &cluster_ids,
                    &batch_ts,
                    column_index,
                    column_type,
                )
                .await?;
                for (cluster_id, top_n) in top_n {
                    top_n_of_clusters.entry(cluster_id).or_default().push(
                        TopElementCountsByColumn {
                            column_index: *column_n,
                            counts: top_n,
                        },
                    );
                }
            }

            let top_n_of_clusters: Vec<TopColumnsOfCluster> = cluster_ids
                .into_iter()
                .map(|cluster_id| {
                    let top_n_of_1_or_n = top_n_of_clusters
                        .get(&cluster_id)
                        .expect("should exist")
                        .clone();
                    TopColumnsOfCluster {
                        cluster_id,
                        columns: top_n_of_1_or_n,
                    }
                })
                .collect();

            top_n_transfer.push(TopMultimaps {
                n_index: *column_n,
                selected: top_n_of_clusters,
            });
        }
        Ok(top_n_transfer)
    }
}
