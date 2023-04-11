use super::{ElementCount, StructuredColumnType, TopElementCountsByColumn};
use crate::{
    self as database,
    schema::{
        cluster, column_description, csv_column_extra, event_range, model, top_n_binary,
        top_n_datetime, top_n_enum, top_n_float, top_n_int, top_n_ipaddr, top_n_text,
    },
    BlockingPgConn, Database, Error,
};
use chrono::NaiveDateTime;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Text};
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use structured::{Element, FloatRange};

#[derive(Debug, QueryableByName, Serialize)]
pub struct SelectedCluster {
    #[diesel(sql_type = Integer)]
    model_id: i32,
    #[diesel(sql_type = Integer)]
    column_index: i32,
    #[diesel(sql_type = Text)]
    cluster_id: String,
    #[diesel(sql_type = BigInt)]
    first_event_id: i64,
    #[diesel(sql_type = BigInt)]
    last_event_id: i64,
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

#[derive(Debug, Queryable)]
struct TopNIntRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: i64,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNEnumRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: String,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNFloatRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value_smallest: f64,
    value_largest: f64,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNTextRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: String,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNBinaryRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: Vec<u8>,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNIpAddrRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: String,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNDateTimeRound {
    cluster_id: String,
    _first_event_id: i64,
    _last_event_id: i64,
    _description_id: i32,
    value: NaiveDateTime,
    count: i64,
}

use cluster::dsl as c_d;
use column_description::dsl as cd_d;
use csv_column_extra::dsl as column_d;
use event_range::dsl as e_d;
use model::dsl as m_d;

#[allow(clippy::too_many_lines)]
pub(crate) fn get_top_multimaps_of_model(
    conn: &mut BlockingPgConn,
    model_id: i32,
    number_of_top_n: usize,
    min_top_n_of_1_to_n: usize,
    time: Option<NaiveDateTime>,
    column_types: Vec<StructuredColumnType>,
) -> Result<Vec<TopMultimaps>, Error> {
    use diesel::RunQueryDsl;

    let column_types: HashMap<usize, String> = column_types
        .into_iter()
        .map(|c| (c.column_index.to_usize().expect("safe"), c.data_type))
        .collect();

    let columns_for_1_to_n = column_d::csv_column_extra
        .select((column_d::column_1, column_d::column_n))
        .filter(column_d::model_id.eq(model_id))
        .first::<(Option<Vec<bool>>, Option<Vec<bool>>)>(conn)?;

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
        let top_table = match column_type {
            "int64" => "top_n_int",
            "enum" => "top_n_enum",
            "float64" => "top_n_float",
            "utf8" => "top_n_text",
            "ipaddr" => "top_n_ipaddr",
            "datetime" => "top_n_datetime",
            "binary" => "top_n_binary",
            _ => unreachable!(),
        };

        let q = if let Some(time) = time {
            format!(
                r#"SELECT model.id as model_id, col.column_index, cluster.cluster_id, first_event_id, last_event_id, top.description_id, COUNT(top.id) as count
                    FROM {} AS top
                    INNER JOIN column_description AS col ON top.description_id = col.id
                    INNER JOIN event_range AS ev ON ev.id = col.event_range_id
                    INNER JOIN cluster ON cluster.id = ev.cluster_id
                    INNER JOIN model ON cluster.model_id = model.id
                    GROUP BY model.id, cluster.cluster_id, col.column_index, first_event_id, last_event_id, top.description_id, cluster.category_id, ev.time
                    HAVING COUNT(top.id) > {} AND model.id = {} AND col.column_index = {} AND cluster.category_id != 2 AND ev.time = '{}'
                    ORDER BY COUNT(top.id) DESC"#,
                top_table, min_top_n_of_1_to_n, model_id, *column_n, time
            )
        } else {
            format!(
                r#"SELECT model.id as model_id, col.column_index, cluster.cluster_id, first_event_id, last_event_id, top.description_id, COUNT(top.id) as count
                    FROM {} AS top
                    INNER JOIN column_description AS col ON top.description_id = col.id
                    INNER JOIN event_range AS ev ON ev.id = col.event_range_id
                    INNER JOIN cluster ON cluster.id = ev.cluster_id
                    INNER JOIN model ON cluster.model_id = model.id
                    GROUP BY model.id, cluster.cluster_id, col.column_index, first_event_id, last_event_id, top.description_id, cluster.category_id, ev.time
                    HAVING COUNT(top.id) > {} AND model.id = {} AND col.column_index = {} AND cluster.category_id != 2
                    ORDER BY COUNT(top.id) DESC"#,
                top_table, min_top_n_of_1_to_n, model_id, *column_n
            )
        };

        let selected_clusters = sql_query(q).load::<SelectedCluster>(conn)?;

        let mut sorted_clusters: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
        for cluster in selected_clusters {
            sorted_clusters
                .entry(cluster.cluster_id)
                .or_insert_with(Vec::<(i64, i64, i64)>::new)
                .push((cluster.first_event_id, cluster.last_event_id, cluster.count));
        }
        for top_n in sorted_clusters.values_mut() {
            top_n.sort_by(|a, b| b.0.cmp(&a.0)); // recent one among rounds is more important. (assuming recent event id is bigger)
            top_n.sort_by(|a, b| b.2.cmp(&a.2));
        }

        let mut sorted_clusters: Vec<(String, i64, i64, i64)> = sorted_clusters // cluster_id, first_event_id, last_event_id, count
            .into_iter()
            .map(|(cluster_id, top_n)| (cluster_id, top_n[0].0, top_n[0].1, top_n[0].2))
            .collect();
        // HIGHLIGHT: take the biggest round only in each cluster
        sorted_clusters.sort_by(|a, b| a.0.cmp(&b.0)); // first, sort clusters by alphabetical order
        sorted_clusters.sort_by(|a, b| b.3.cmp(&a.3)); // then, sort by count
        sorted_clusters.truncate(number_of_top_n);

        let cluster_ids: Vec<String> = sorted_clusters.iter().map(|c| c.0.clone()).collect();
        let first_event_ids: Vec<i64> = sorted_clusters.iter().map(|c| c.1).collect();
        let last_event_ids: Vec<i64> = sorted_clusters.iter().map(|c| c.2).collect();

        let mut top_n_of_clusters: HashMap<String, Vec<TopElementCountsByColumn>> = HashMap::new();
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
                conn,
                model_id,
                &cluster_ids,
                &first_event_ids,
                &last_event_ids,
                column_index,
                column_type,
            )?;
            for (cluster_id, top_n) in top_n {
                top_n_of_clusters
                    .entry(cluster_id)
                    .or_insert_with(Vec::<TopElementCountsByColumn>::new)
                    .push(TopElementCountsByColumn {
                        column_index: *column_1,
                        counts: top_n,
                    });
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
                conn,
                model_id,
                &cluster_ids,
                &first_event_ids,
                &last_event_ids,
                column_index,
                column_type,
            )?;
            for (cluster_id, top_n) in top_n {
                top_n_of_clusters
                    .entry(cluster_id)
                    .or_insert_with(Vec::<TopElementCountsByColumn>::new)
                    .push(TopElementCountsByColumn {
                        column_index: *column_n,
                        counts: top_n,
                    });
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

macro_rules! get_top_n_of_column_by_round {
    ($conn:expr, $top_d:ident, $top_table:ident, $load_type:ty, $d:expr, $c:expr, $f_ei:expr, $l_ei:expr, $index:expr, $func:tt, $top_n:expr) => {{
        use diesel::RunQueryDsl;

        let top_n = $top_d::$top_table
            .inner_join(cd_d::column_description.on(cd_d::id.eq($top_d::description_id)))
            .inner_join(e_d::event_range.on(e_d::id.eq(cd_d::event_range_id)))
            .inner_join(c_d::cluster.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(m_d::model.on(m_d::id.eq(c_d::model_id)))
            .filter(
                m_d::id
                    .eq($d)
                    .and(c_d::cluster_id.eq_any($c))
                    .and(e_d::first_event_id.eq_any($f_ei))
                    .and(e_d::last_event_id.eq_any($l_ei))
                    .and(cd_d::column_index.eq($index)),
            )
            .select((
                c_d::cluster_id,
                e_d::first_event_id,
                e_d::last_event_id,
                $top_d::description_id,
                $top_d::value,
                $top_d::count,
            ))
            .load::<$load_type>($conn)?;

        let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
        for t in &top_n {
            let value;
            $func!(value, &t.value);

            top_n_by_cluster
                .entry(t.cluster_id.clone())
                .or_insert_with(Vec::<ElementCount>::new)
                .push(ElementCount {
                    value,
                    count: t.count,
                });
        }

        for (_, top_n) in top_n_by_cluster.iter_mut() {
            top_n.sort_by(|a, b| a.value.cmp(&b.value));
            top_n.sort_by(|a, b| b.count.cmp(&a.count));
        }

        $top_n = Ok(top_n_by_cluster);
    }};
}

macro_rules! async_get_top_n_of_column_by_round {
    ($conn:expr, $top_d:ident, $top_table:ident, $load_type:ty, $d:expr, $c:expr, $f_ei:expr, $l_ei:expr, $index:expr, $func:tt, $top_n:expr) => {{
        use diesel_async::RunQueryDsl;

        let top_n = $top_d::$top_table
            .inner_join(cd_d::column_description.on(cd_d::id.eq($top_d::description_id)))
            .inner_join(e_d::event_range.on(e_d::id.eq(cd_d::event_range_id)))
            .inner_join(c_d::cluster.on(c_d::id.eq(e_d::cluster_id)))
            .inner_join(m_d::model.on(m_d::id.eq(c_d::model_id)))
            .filter(
                m_d::id
                    .eq($d)
                    .and(c_d::cluster_id.eq_any($c))
                    .and(e_d::first_event_id.eq_any($f_ei))
                    .and(e_d::last_event_id.eq_any($l_ei))
                    .and(cd_d::column_index.eq($index)),
            )
            .select((
                c_d::cluster_id,
                e_d::first_event_id,
                e_d::last_event_id,
                $top_d::description_id,
                $top_d::value,
                $top_d::count,
            ))
            .load::<$load_type>($conn)
            .await?;

        let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
        for t in &top_n {
            let value;
            $func!(value, &t.value);

            top_n_by_cluster
                .entry(t.cluster_id.clone())
                .or_insert_with(Vec::<ElementCount>::new)
                .push(ElementCount {
                    value,
                    count: t.count,
                });
        }

        for (_, top_n) in top_n_by_cluster.iter_mut() {
            top_n.sort_by(|a, b| a.value.cmp(&b.value));
            top_n.sort_by(|a, b| b.count.cmp(&a.count));
        }

        $top_n = Ok(top_n_by_cluster);
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
fn get_top_n(
    conn: &mut BlockingPgConn,
    model_id: i32,
    cluster_ids: &[String],
    first_event_ids: &[i64],
    last_event_ids: &[i64],
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
                TopNIntRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
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
                TopNEnumRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "float64" => {
            use diesel::RunQueryDsl;
            use top_n_float::dsl as ti_d;
            let top_n = ti_d::top_n_float
                .inner_join(cd_d::column_description.on(cd_d::id.eq(ti_d::description_id)))
                .inner_join(e_d::event_range.on(e_d::id.eq(cd_d::event_range_id)))
                .inner_join(c_d::cluster.on(c_d::id.eq(e_d::cluster_id)))
                .inner_join(m_d::model.on(m_d::id.eq(c_d::model_id)))
                .filter(
                    m_d::id
                        .eq(model_id)
                        .and(c_d::cluster_id.eq_any(cluster_ids))
                        .and(e_d::first_event_id.eq_any(first_event_ids))
                        .and(e_d::last_event_id.eq_any(last_event_ids))
                        .and(cd_d::column_index.eq(&column_index)),
                )
                .select((
                    c_d::cluster_id,
                    e_d::first_event_id,
                    e_d::last_event_id,
                    ti_d::description_id,
                    ti_d::value_smallest,
                    ti_d::value_largest,
                    ti_d::count,
                ))
                .load::<TopNFloatRound>(conn)?;

            let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
            for t in &top_n {
                let smallest = t.value_smallest;
                let largest = t.value_largest;

                top_n_by_cluster
                    .entry(t.cluster_id.clone())
                    .or_insert_with(Vec::<ElementCount>::new)
                    .push(ElementCount {
                        value: Element::FloatRange(FloatRange { smallest, largest }).to_string(),
                        count: t.count,
                    });
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
                TopNTextRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
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
                TopNIpAddrRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
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
                TopNDateTimeRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
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
                TopNBinaryRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_utf8,
                top_n
            );
            top_n
        }
        _ => unreachable!(),
    }
}

#[allow(clippy::too_many_lines)]
async fn async_get_top_n(
    conn: &mut diesel_async::pg::AsyncPgConnection,
    model_id: i32,
    cluster_ids: &[String],
    first_event_ids: &[i64],
    last_event_ids: &[i64],
    column_index: i32,
    column_type: &str,
) -> Result<HashMap<String, Vec<ElementCount>>, database::Error> {
    match column_type {
        "int64" => {
            use top_n_int::dsl as ti_d;
            let top_n;
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_int,
                TopNIntRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_to_string,
                top_n
            );
            top_n
        }
        "enum" => {
            use top_n_enum::dsl as ti_d;
            let top_n;
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_enum,
                TopNEnumRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "float64" => {
            use diesel_async::RunQueryDsl;
            use top_n_float::dsl as ti_d;

            let top_n = ti_d::top_n_float
                .inner_join(cd_d::column_description.on(cd_d::id.eq(ti_d::description_id)))
                .inner_join(e_d::event_range.on(e_d::id.eq(cd_d::event_range_id)))
                .inner_join(c_d::cluster.on(c_d::id.eq(e_d::cluster_id)))
                .inner_join(m_d::model.on(m_d::id.eq(c_d::model_id)))
                .filter(
                    m_d::id
                        .eq(model_id)
                        .and(c_d::cluster_id.eq_any(cluster_ids))
                        .and(e_d::first_event_id.eq_any(first_event_ids))
                        .and(e_d::last_event_id.eq_any(last_event_ids))
                        .and(cd_d::column_index.eq(&column_index)),
                )
                .select((
                    c_d::cluster_id,
                    e_d::first_event_id,
                    e_d::last_event_id,
                    ti_d::description_id,
                    ti_d::value_smallest,
                    ti_d::value_largest,
                    ti_d::count,
                ))
                .load::<TopNFloatRound>(conn)
                .await?;

            let mut top_n_by_cluster: HashMap<String, Vec<ElementCount>> = HashMap::new();
            for t in &top_n {
                let smallest = t.value_smallest;
                let largest = t.value_largest;

                top_n_by_cluster
                    .entry(t.cluster_id.clone())
                    .or_insert_with(Vec::<ElementCount>::new)
                    .push(ElementCount {
                        value: Element::FloatRange(FloatRange { smallest, largest }).to_string(),
                        count: t.count,
                    });
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
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_text,
                TopNTextRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "ipaddr" => {
            use top_n_ipaddr::dsl as ti_d;
            let top_n;
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_ipaddr,
                TopNIpAddrRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_clone,
                top_n
            );
            top_n
        }
        "datetime" => {
            use top_n_datetime::dsl as ti_d;
            let top_n;
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_datetime,
                TopNDateTimeRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
                &column_index,
                get_value_of_top_n_round_by_to_string,
                top_n
            );
            top_n
        }
        "binary" => {
            use top_n_binary::dsl as ti_d;
            let top_n;
            async_get_top_n_of_column_by_round!(
                conn,
                ti_d,
                top_n_binary,
                TopNBinaryRound,
                model_id,
                cluster_ids,
                first_event_ids,
                last_event_ids,
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
    #[allow(clippy::too_many_lines)]
    pub async fn get_top_multimaps_of_model(
        &self,
        model_id: i32,
        number_of_top_n: usize,
        min_top_n_of_1_to_n: usize,
        time: Option<NaiveDateTime>,
        column_types: Vec<StructuredColumnType>,
    ) -> Result<Vec<TopMultimaps>, Error> {
        use diesel_async::RunQueryDsl;

        let mut conn = self.pool.get_diesel_conn().await?;
        let column_types: HashMap<usize, String> = column_types
            .into_iter()
            .map(|c| (c.column_index.to_usize().expect("safe"), c.data_type))
            .collect();

        let columns_for_1_to_n = column_d::csv_column_extra
            .select((column_d::column_1, column_d::column_n))
            .filter(column_d::model_id.eq(model_id))
            .first::<(Option<Vec<bool>>, Option<Vec<bool>>)>(&mut conn)
            .await?;

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
            let top_table = match column_type {
                "int64" => "top_n_int",
                "enum" => "top_n_enum",
                "float64" => "top_n_float",
                "utf8" => "top_n_text",
                "ipaddr" => "top_n_ipaddr",
                "datetime" => "top_n_datetime",
                "binary" => "top_n_binary",
                _ => unreachable!(),
            };

            let q = if let Some(time) = time {
                format!(
                    r#"SELECT model.id as model_id, col.column_index, cluster.cluster_id, first_event_id, last_event_id, top.description_id, COUNT(top.id) as count
                        FROM {} AS top
                        INNER JOIN column_description AS col ON top.description_id = col.id
                        INNER JOIN event_range AS ev ON ev.id = col.event_range_id
                        INNER JOIN cluster ON cluster.id = ev.cluster_id
                        INNER JOIN model ON cluster.model_id = model.id
                        GROUP BY model.id, cluster.cluster_id, col.column_index, first_event_id, last_event_id, top.description_id, cluster.category_id, ev.time
                        HAVING COUNT(top.id) > {} AND model.id = {} AND col.column_index = {} AND cluster.category_id != 2 AND ev.time = '{}'
                        ORDER BY COUNT(top.id) DESC"#,
                    top_table, min_top_n_of_1_to_n, model_id, *column_n, time
                )
            } else {
                format!(
                    r#"SELECT model.id as model_id, col.column_index, cluster.cluster_id, first_event_id, last_event_id, top.description_id, COUNT(top.id) as count
                        FROM {} AS top
                        INNER JOIN column_description AS col ON top.description_id = col.id
                        INNER JOIN event_range AS ev ON ev.id = col.event_range_id
                        INNER JOIN cluster ON cluster.id = ev.cluster_id
                        INNER JOIN model ON cluster.model_id = model.id
                        GROUP BY model.id, cluster.cluster_id, col.column_index, first_event_id, last_event_id, top.description_id, cluster.category_id, ev.time
                        HAVING COUNT(top.id) > {} AND model.id = {} AND col.column_index = {} AND cluster.category_id != 2
                        ORDER BY COUNT(top.id) DESC"#,
                    top_table, min_top_n_of_1_to_n, model_id, *column_n
                )
            };

            let selected_clusters = sql_query(q).load::<SelectedCluster>(&mut conn).await?;

            let mut sorted_clusters: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
            for cluster in selected_clusters {
                sorted_clusters
                    .entry(cluster.cluster_id)
                    .or_insert_with(Vec::<(i64, i64, i64)>::new)
                    .push((cluster.first_event_id, cluster.last_event_id, cluster.count));
            }
            for top_n in sorted_clusters.values_mut() {
                top_n.sort_by(|a, b| b.0.cmp(&a.0)); // recent one among rounds is more important. (assuming recent event id is bigger)
                top_n.sort_by(|a, b| b.2.cmp(&a.2));
            }

            let mut sorted_clusters: Vec<(String, i64, i64, i64)> = sorted_clusters // cluster_id, first_event_id, last_event_id, count
                .into_iter()
                .map(|(cluster_id, top_n)| (cluster_id, top_n[0].0, top_n[0].1, top_n[0].2))
                .collect();
            // HIGHLIGHT: take the biggest round only in each cluster
            sorted_clusters.sort_by(|a, b| a.0.cmp(&b.0)); // first, sort clusters by alphabetical order
            sorted_clusters.sort_by(|a, b| b.3.cmp(&a.3)); // then, sort by count
            sorted_clusters.truncate(number_of_top_n);

            let cluster_ids: Vec<String> = sorted_clusters.iter().map(|c| c.0.clone()).collect();
            let first_event_ids: Vec<i64> = sorted_clusters.iter().map(|c| c.1).collect();
            let last_event_ids: Vec<i64> = sorted_clusters.iter().map(|c| c.2).collect();

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
                let top_n = async_get_top_n(
                    &mut conn,
                    model_id,
                    &cluster_ids,
                    &first_event_ids,
                    &last_event_ids,
                    column_index,
                    column_type,
                )
                .await?;
                for (cluster_id, top_n) in top_n {
                    top_n_of_clusters
                        .entry(cluster_id)
                        .or_insert_with(Vec::<TopElementCountsByColumn>::new)
                        .push(TopElementCountsByColumn {
                            column_index: *column_1,
                            counts: top_n,
                        });
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
                let top_n = async_get_top_n(
                    &mut conn,
                    model_id,
                    &cluster_ids,
                    &first_event_ids,
                    &last_event_ids,
                    column_index,
                    column_type,
                )
                .await?;
                for (cluster_id, top_n) in top_n {
                    top_n_of_clusters
                        .entry(cluster_id)
                        .or_insert_with(Vec::<TopElementCountsByColumn>::new)
                        .push(TopElementCountsByColumn {
                            column_index: *column_n,
                            counts: top_n,
                        });
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
