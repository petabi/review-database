use super::{
    filter_by_whitelists, get_cluster_sizes, get_limited_cluster_ids, limited_top_n_of_clusters,
    total_of_top_n, TopElementCountsByColumn, TopNOfMultipleCluster, ValueType,
    DEFAULT_NUMBER_OF_CLUSTER, DEFAULT_NUMBER_OF_COLUMN, DEFAULT_PORTION_OF_CLUSTER,
    DEFAULT_PORTION_OF_TOP_N,
};
use crate::{
    csv_indicator::get_whitelists,
    schema::{
        cluster, column_description, csv_column_extra, event_range, top_n_binary, top_n_datetime,
        top_n_enum, top_n_float, top_n_int, top_n_ipaddr, top_n_text,
    },
    BlockingPgConn, Error, StructuredColumnType,
};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use num_traits::ToPrimitive;
use std::collections::HashSet;
use structured::{Element, FloatRange};

use cluster::dsl as c_d;
use column_description::dsl as col_d;
use event_range::dsl as e_d;

macro_rules! get_top_n_of_column {
    ($conn:expr, $top_d:ident, $top_table:ident, $value_type:ty, $c:expr, $i:expr, $tc:expr, $time:expr) => {{
        let query = c_d::cluster
            .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
            .inner_join($top_d::$top_table.on(top_d::description_id.eq(col_d::id)))
            .select((
                e_d::cluster_id,
                col_d::column_index,
                col_d::id,
                top_d::value,
                top_d::count,
            ));
        let top_n = if let Some(time) = $time {
            query
                .filter(
                    c_d::id
                        .eq_any($c)
                        .and(e_d::time.eq(time))
                        .and(col_d::column_index.eq($i)),
                )
                .load::<(i32, i32, i32, $value_type, i64)>($conn)?
        } else {
            query
                .filter(c_d::id.eq_any($c).and(col_d::column_index.eq($i)))
                .load::<(i32, i32, i32, $value_type, i64)>($conn)?
        };

        let mut top_n: Vec<TopNOfMultipleCluster> = top_n
            .into_iter()
            .map(|t| {
                let value = ValueType::into_string(t.3);
                TopNOfMultipleCluster {
                    cluster_id: t.0,
                    column_index: t.1,
                    _description_id: t.2,
                    value,
                    count: t.4,
                }
            })
            .collect();
        $tc.append(&mut top_n);
    }};
}

pub(super) fn get_columns_for_top_n(conn: &mut BlockingPgConn, model_id: i32) -> Vec<i32> {
    use csv_column_extra::dsl as column_d;

    match column_d::csv_column_extra
        .select(column_d::column_top_n)
        .filter(column_d::model_id.eq(model_id))
        .first::<Option<Vec<bool>>>(conn)
    {
        Ok(columns) => columns.map_or_else(Vec::new, |c| {
            c.iter()
                .enumerate()
                .filter_map(|(index, is)| {
                    if *is {
                        Some(index.to_i32().expect("column index < i32::max"))
                    } else {
                        None
                    }
                })
                .collect()
        }),
        Err(_) => Vec::new(),
    }
}

#[allow(clippy::type_complexity)]
fn top_n_of_float(
    conn: &mut BlockingPgConn,
    cluster_ids: &[i32],
    index: i32,
    time: Option<NaiveDateTime>,
) -> Result<Vec<(i32, i32, i32, f64, f64, i64)>, diesel::result::Error> {
    use top_n_float::dsl as top_d;
    time.as_ref().map_or(
        c_d::cluster
            .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
            .inner_join(top_d::top_n_float.on(top_d::description_id.eq(col_d::id)))
            .select((
                e_d::cluster_id,
                col_d::column_index,
                col_d::id,
                top_d::value_smallest,
                top_d::value_largest,
                top_d::count,
            ))
            .filter(
                c_d::id
                    .eq_any(cluster_ids)
                    .and(col_d::column_index.eq(&index)),
            )
            .load::<(i32, i32, i32, f64, f64, i64)>(conn),
        |time| {
            c_d::cluster
                .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
                .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
                .inner_join(top_d::top_n_float.on(top_d::description_id.eq(col_d::id)))
                .select((
                    e_d::cluster_id,
                    col_d::column_index,
                    col_d::id,
                    top_d::value_smallest,
                    top_d::value_largest,
                    top_d::count,
                ))
                .filter(
                    c_d::id
                        .eq_any(cluster_ids)
                        .and(e_d::time.eq(time))
                        .and(col_d::column_index.eq(&index)),
                )
                .load::<(i32, i32, i32, f64, f64, i64)>(conn)
        },
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn get_top_columns_of_model(
    conn: &mut BlockingPgConn,
    model_id: i32,
    number_of_top_n: usize,
    time: Option<NaiveDateTime>,
    portion_of_clusters: Option<f64>,
    portion_of_top_n: Option<f64>,
    mut column_types: Vec<StructuredColumnType>,
) -> Result<Vec<TopElementCountsByColumn>, Error> {
    let columns_for_top_n = get_columns_for_top_n(conn, model_id);
    let columns_for_top_n: HashSet<i32> = columns_for_top_n.into_iter().collect();
    column_types.retain(|c| columns_for_top_n.get(&c.column_index).is_some());

    let cluster_sizes = get_cluster_sizes(conn, model_id)?;
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
                    conn,
                    top_d,
                    top_n_int,
                    i64,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            "enum" => {
                use top_n_enum::dsl as top_d;
                get_top_n_of_column!(
                    conn,
                    top_d,
                    top_n_enum,
                    String,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            "float64" => {
                let top_n = top_n_of_float(conn, &cluster_ids, index, time)?;
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
                    conn,
                    top_d,
                    top_n_text,
                    String,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            "ipaddr" => {
                use top_n_ipaddr::dsl as top_d;
                get_top_n_of_column!(
                    conn,
                    top_d,
                    top_n_ipaddr,
                    String,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            "datetime" => {
                use top_n_datetime::dsl as top_d;
                get_top_n_of_column!(
                    conn,
                    top_d,
                    top_n_datetime,
                    NaiveDateTime,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            "binary" => {
                use top_n_binary::dsl as top_d;
                get_top_n_of_column!(
                    conn,
                    top_d,
                    top_n_binary,
                    Vec<u8>,
                    &cluster_ids,
                    &index,
                    top_n_of_cluster,
                    time
                );
            }
            _ => unreachable!(),
        }
    }

    let top_n = total_of_top_n(top_n_of_cluster);
    let top_n = limited_top_n_of_clusters(
        top_n,
        portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N),
        DEFAULT_NUMBER_OF_COLUMN,
    );
    let column_indices: Vec<usize> = top_n.keys().copied().collect();
    let whitelists = get_whitelists(conn, model_id, &column_indices);
    Ok(filter_by_whitelists(top_n, &whitelists, number_of_top_n))
}
