mod column;
mod ipaddr;
mod one_to_n;
mod score;
mod time_series;

pub(crate) use self::column::get_top_columns_of_model;
pub(crate) use self::ipaddr::{get_top_ip_addresses_of_cluster, get_top_ip_addresses_of_model};
pub(crate) use self::one_to_n::get_top_multimaps_of_model;
pub use self::one_to_n::{TopColumnsOfCluster, TopMultimaps};
pub(crate) use self::score::get_top_clusters_by_score;
pub use self::score::{ClusterScore, ClusterScoreSet};
pub(crate) use self::time_series::get_top_cluster_time_series;
pub use self::time_series::{ClusterTrend, LineSegment, Regression, TopTrendsByColumn};
use super::{BlockingPgConn, Database, Error, Type};
use bb8_postgres::tokio_postgres::row::Row;
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

const DEFAULT_PORTION_OF_CLUSTER: f64 = 0.3;
const DEFAULT_NUMBER_OF_CLUSTER: usize = 10;
const DEFAULT_PORTION_OF_TOP_N: f64 = 1.0;
const DEFAULT_NUMBER_OF_COLUMN: usize = 30;

trait ValueType {
    fn into_string(self) -> String;
}

impl ValueType for NaiveDateTime {
    fn into_string(self) -> String {
        self.to_string()
    }
}

impl ValueType for i64 {
    fn into_string(self) -> String {
        self.to_string()
    }
}

impl ValueType for String {
    fn into_string(self) -> String {
        self
    }
}

impl ValueType for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8_lossy(&self).to_string()
    }
}

impl From<Row> for StructuredColumnType {
    fn from(row: Row) -> Self {
        let column_index = row.get("column_index");
        let type_id: i32 = row.get("type_id");
        let data_type = match type_id {
            1 => "int64",
            2 => "enum",
            3 => "float64",
            4 => "utf8",
            5 => "ipaddr",
            6 => "datetime",
            7 => "binary",
            _ => unreachable!(),
        };
        Self {
            column_index,
            data_type: data_type.to_string(),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct ElementCount {
    pub value: String,
    pub count: i64,
}

#[derive(Deserialize, Serialize)]
pub struct StructuredColumnType {
    pub column_index: i32,
    pub data_type: String,
}

#[derive(Clone, Deserialize)]
pub struct TopElementCountsByColumn {
    pub column_index: usize,
    pub counts: Vec<ElementCount>,
}

#[derive(Debug, Queryable)]
struct TopNOfCluster {
    column_index: i32,
    _description_id: i32,
    value: String,
    count: i64,
}

#[derive(Debug, Queryable)]
struct TopNOfMultipleCluster {
    cluster_id: i32,
    column_index: i32,
    _description_id: i32,
    value: String,
    count: i64,
}

#[derive(Debug, Queryable)]
struct ClusterSize {
    id: i32,
    size: i64,
}

impl Database {
    pub async fn get_column_types_of_model(
        &self,
        model_id: i32,
    ) -> Result<Vec<StructuredColumnType>, Error> {
        let mut conn = self.pool.get().await?;
        let txn = conn.build_transaction().await?;
        let cluster_ids = txn
            .select_in(
                "cluster",
                &["id"],
                &[("model_id", Type::INT4)],
                &[],
                &[],
                &[&model_id],
            )
            .await?
            .into_iter()
            .map(|r| r.get(0))
            .collect::<Vec<i32>>();
        let event_range_ids = txn
            .select_in(
                "event_range",
                &["id"],
                &[],
                &[("cluster_id", Type::INT4_ARRAY)],
                &[],
                &[&cluster_ids],
            )
            .await?;
        let Some(event_range_id) = event_range_ids.first() else {
            return Ok(Vec::new());
        };
        let event_range_id: i32 = match event_range_id.get(0) {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };
        let result = txn
            .select_in(
                "column_description",
                &["column_index", "type_id"],
                &[("event_range_id", Type::INT4)],
                &[],
                &[],
                &[&event_range_id],
            )
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        txn.commit().await?;

        Ok(result)
    }
}

fn get_cluster_sizes(conn: &mut BlockingPgConn, model_id: i32) -> Result<Vec<ClusterSize>, Error> {
    use super::schema::cluster::dsl;
    use diesel::RunQueryDsl;

    let cluster_sizes = dsl::cluster
        .select((dsl::id, dsl::size))
        .filter(dsl::model_id.eq(model_id).and(dsl::category_id.ne(2)))
        .order_by(dsl::size.desc())
        .then_order_by(dsl::id.asc())
        .load::<ClusterSize>(conn)?;

    Ok(cluster_sizes)
}

async fn async_get_cluster_sizes(
    conn: &mut diesel_async::pg::AsyncPgConnection,
    model_id: i32,
) -> Result<Vec<ClusterSize>, diesel::result::Error> {
    use super::schema::cluster::dsl;
    use diesel_async::RunQueryDsl;

    dsl::cluster
        .select((dsl::id, dsl::size))
        .filter(dsl::model_id.eq(model_id).and(dsl::category_id.ne(2)))
        .order_by(dsl::size.desc())
        .then_order_by(dsl::id.asc())
        .load::<ClusterSize>(conn)
        .await
}

fn get_limited_cluster_ids(
    cluster_sizes: &[ClusterSize],
    portion_of_clusters: f64,
    number_of_clusters: usize,
) -> Vec<i32> {
    let total_sizes: i64 = cluster_sizes.iter().map(|v| v.size).sum();

    let size_including_clusters =
        i64::from_f64((total_sizes.to_f64().unwrap_or(f64::MAX) * portion_of_clusters).trunc())
            .unwrap_or_else(|| i64::from_usize(number_of_clusters).unwrap_or(i64::MAX));

    let mut sum_sizes = 0;
    let mut index_included: usize = 0;
    for (index, c) in cluster_sizes.iter().enumerate() {
        sum_sizes += c.size;
        index_included = index;
        if sum_sizes > size_including_clusters {
            break;
        }
    }

    let cluster_ids: Vec<i32> = cluster_sizes
        .iter()
        .take(index_included + 1)
        .map(|c| c.id)
        .collect();

    cluster_ids
}

fn total_of_top_n(
    top_n_of_multiple_cluster: Vec<TopNOfMultipleCluster>,
) -> HashMap<i32, HashMap<usize, HashMap<String, i64>>> {
    let mut top_n_of_clusters: HashMap<i32, HashMap<usize, HashMap<String, i64>>> = HashMap::new();
    // (i32, (usize, (String, BigDecimal))) = (cluster_id, (column_index, (Ip Address, size)))
    for v in top_n_of_multiple_cluster {
        if let (Some(column_index), value, count) = (v.column_index.to_usize(), v.value, v.count) {
            *top_n_of_clusters
                .entry(v.cluster_id)
                .or_insert_with(HashMap::<usize, HashMap<String, i64>>::new)
                .entry(column_index)
                .or_insert_with(HashMap::<String, i64>::new)
                .entry(value)
                .or_insert(0) += count;
        }
    }

    top_n_of_clusters
}

fn limited_top_n_of_clusters(
    top_n_of_clusters: HashMap<i32, HashMap<usize, HashMap<String, i64>>>,
    limit_rate: f64,
    default_number: usize,
) -> HashMap<usize, HashMap<String, i64>> {
    let mut top_n_total: HashMap<usize, HashMap<String, i64>> = HashMap::new(); // (usize, (String, BigDecimal)) = (column_index, (Ip Address, size))
    for (_, top_n) in top_n_of_clusters {
        for (column_index, t) in top_n {
            let total_sizes: i64 = t.iter().map(|v| v.1).sum();
            let mut top_n: Vec<(String, i64)> = t.into_iter().collect();
            top_n.sort_by(|a, b| b.1.cmp(&a.1));

            let size_including_ips =
                i64::from_f64((total_sizes.to_f64().unwrap_or(0.0) * limit_rate).trunc())
                    .unwrap_or_else(|| i64::from_usize(default_number).unwrap_or(i64::MAX));

            let mut sum_sizes = 0;
            for (ip, size) in top_n {
                sum_sizes += size;
                *top_n_total
                    .entry(column_index)
                    .or_insert_with(HashMap::<String, i64>::new)
                    .entry(ip)
                    .or_insert(0) += size;
                if sum_sizes > size_including_ips {
                    break;
                }
            }
        }
    }

    top_n_total
}

fn filter_by_whitelists(
    top_n_total: HashMap<usize, HashMap<String, i64>>,
    whitelists: &HashMap<usize, String>,
    number_of_top_n: usize,
) -> Vec<TopElementCountsByColumn> {
    let mut top_n: Vec<TopElementCountsByColumn> = top_n_total
        .into_iter()
        .map(|(column_index, map)| {
            let whitelist = whitelists
                .get(&column_index)
                .and_then(|w| serde_json::from_str::<HashSet<String>>(w).ok());
            let mut top_n: Vec<ElementCount> = map
                .into_iter()
                .filter_map(|(dsc, size)| {
                    if let Some(list) = &whitelist {
                        if list.get(&dsc).is_some() {
                            return None;
                        }
                    }
                    Some(ElementCount {
                        value: dsc,
                        count: size,
                    })
                })
                .collect();
            top_n.sort_by(|a, b| a.value.cmp(&b.value)); // this makes lists in the same alphabetical order
            top_n.sort_by_key(|a| Reverse(a.count));
            top_n.truncate(number_of_top_n);
            TopElementCountsByColumn {
                column_index,
                counts: top_n,
            }
        })
        .collect();
    top_n.sort_by(|a, b| a.column_index.cmp(&b.column_index));

    top_n
}
