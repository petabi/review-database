use super::{
    filter_by_whitelists, get_cluster_sizes, get_limited_cluster_ids, limited_top_n_of_clusters,
    total_of_top_n, ElementCount, TopElementCountsByColumn, TopNOfCluster, TopNOfMultipleCluster,
    DEFAULT_NUMBER_OF_CLUSTER, DEFAULT_NUMBER_OF_COLUMN, DEFAULT_PORTION_OF_CLUSTER,
    DEFAULT_PORTION_OF_TOP_N,
};
use crate::{
    self as database,
    csv_indicator::get_whitelists,
    schema::{cluster, column_description, event_range, top_n_ipaddr},
    BlockingPgConn, Error,
};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use num_traits::ToPrimitive;
use std::collections::HashMap;

use cluster::dsl as c_d;
use column_description::dsl as col_d;
use event_range::dsl as e_d;
use top_n_ipaddr::dsl as top_d;

pub(crate) fn get_top_ip_addresses_of_cluster(
    conn: &mut BlockingPgConn,
    model_id: i32,
    cluster_id: &str,
    size: usize,
) -> Result<Vec<TopElementCountsByColumn>, Error> {
    let values = c_d::cluster
        .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
        .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
        .inner_join(top_d::top_n_ipaddr.on(top_d::description_id.eq(col_d::id)))
        .select((col_d::column_index, col_d::id, top_d::value, top_d::count))
        .filter(
            c_d::model_id
                .eq(model_id)
                .and(c_d::cluster_id.eq(cluster_id)),
        )
        .load::<TopNOfCluster>(conn)?;

    let mut top_n: HashMap<usize, HashMap<String, i64>> = HashMap::new(); // String: Ip Address
    for v in values {
        if let (Some(column_index), value, count) = (v.column_index.to_usize(), v.value, v.count) {
            *top_n
                .entry(column_index)
                .or_insert_with(HashMap::<String, i64>::new)
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
            top_n.sort_by(|a, b| b.count.cmp(&a.count));
            top_n.truncate(size);
            TopElementCountsByColumn {
                column_index: t.0,
                counts: top_n,
            }
        })
        .collect();
    top_n.sort_by(|a, b| a.column_index.cmp(&b.column_index));
    Ok(top_n)
}

pub(crate) fn get_top_ip_addresses_of_model(
    conn: &mut BlockingPgConn,
    model_id: i32,
    size: usize,
    time: Option<NaiveDateTime>,
    portion_of_clusters: Option<f64>,
    portion_of_top_n: Option<f64>,
) -> Result<Vec<TopElementCountsByColumn>, Error> {
    let cluster_sizes = get_cluster_sizes(conn, model_id)?;
    let cluster_ids = get_limited_cluster_ids(
        &cluster_sizes,
        portion_of_clusters.unwrap_or(DEFAULT_PORTION_OF_CLUSTER),
        DEFAULT_NUMBER_OF_CLUSTER,
    );

    let top_n = get_top_n_of_multiple_clusters(conn, &cluster_ids, time)?;
    let top_n = total_of_top_n(top_n);
    let top_n = limited_top_n_of_clusters(
        top_n,
        portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N),
        DEFAULT_NUMBER_OF_COLUMN,
    );
    let column_indices: Vec<usize> = top_n.keys().copied().collect();
    let whitelists = get_whitelists(conn, model_id, &column_indices);
    Ok(filter_by_whitelists(top_n, &whitelists, size))
}

fn get_top_n_of_multiple_clusters(
    conn: &mut BlockingPgConn,
    cluster_ids: &[i32],
    time: Option<NaiveDateTime>,
) -> Result<Vec<TopNOfMultipleCluster>, database::Error> {
    let top_n_of_multiple_clusters = if let Some(time) = time {
        c_d::cluster
            .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
            .inner_join(top_d::top_n_ipaddr.on(top_d::description_id.eq(col_d::id)))
            .select((
                c_d::id,
                col_d::column_index,
                col_d::id,
                top_d::value,
                top_d::count,
            ))
            .filter(e_d::time.eq(time).and(c_d::id.eq_any(cluster_ids)))
            .load::<TopNOfMultipleCluster>(conn)?
    } else {
        c_d::cluster
            .inner_join(e_d::event_range.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(col_d::column_description.on(col_d::event_range_id.eq(e_d::id)))
            .inner_join(top_d::top_n_ipaddr.on(top_d::description_id.eq(col_d::id)))
            .select((
                c_d::id,
                col_d::column_index,
                col_d::id,
                top_d::value,
                top_d::count,
            ))
            .filter(c_d::id.eq_any(cluster_ids))
            .load::<TopNOfMultipleCluster>(conn)?
    };

    Ok(top_n_of_multiple_clusters)
}
