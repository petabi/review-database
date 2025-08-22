mod one_to_n;
mod time_series;

use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::pg::AsyncPgConnection;
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

pub use self::one_to_n::{TopColumnsOfCluster, TopMultimaps};
#[allow(deprecated)]
pub use self::time_series::{ClusterTrend, LineSegment, Regression, TopTrendsByColumn};
use super::{Database, Error};

const DEFAULT_PORTION_OF_CLUSTER: f64 = 0.3;
const DEFAULT_NUMBER_OF_CLUSTER: usize = 10;

impl From<(i32, i32)> for StructuredColumnType {
    fn from((column_index, type_id): (i32, i32)) -> Self {
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
struct ClusterSize {
    id: i32,
    size: i64,
}

impl Database {
    /// Loads `(id, cluster_id)` for all the clusters in the model that satisfy the given conditions.
    /// - `model`: The model ID to filter clusters by.
    /// - `cluster_id`: Optional cluster ID to filter clusters by.
    ///
    /// Returns a vector of tuples containing the cluster ID
    ///     and its corresponding string ID in ascending order of `id` and `cluster_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_cluster_ids(
        &self,
        model: i32,
        cluster_id: Option<&str>,
    ) -> Result<Vec<(i32, String)>, Error> {
        use diesel_async::RunQueryDsl;

        use crate::schema::cluster::dsl;
        let mut conn = self.pool.get().await?;
        let mut query = dsl::cluster
            .filter(dsl::model_id.eq(&model).and(dsl::category_id.ne(2)))
            .select((dsl::id, dsl::cluster_id))
            .order_by(dsl::id.asc())
            .then_order_by(dsl::cluster_id.asc())
            .into_boxed();
        if let Some(cluster_id) = cluster_id {
            query = query.filter(dsl::cluster_id.eq(cluster_id));
        }
        Ok(query.load::<(i32, String)>(&mut conn).await?)
    }

    /// Loads `id` for all the clusters in the model that satisfy the given conditions.
    /// - `model`: The model ID to filter clusters by.
    /// - `portion_of_clusters`: The portion of clusters to limit the results to, as a fraction (0.0 to 1.0). Default is 0.3.
    ///
    /// Returns a vector of cluster IDs, limited by the specified portion of clusters.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_cluster_ids_with_size_limit(
        &self,
        model: i32,
        portion_of_clusters: Option<f64>,
    ) -> Result<Vec<i32>, Error> {
        let mut conn = self.pool.get().await?;
        let cluster_sizes = get_cluster_sizes(&mut conn, model).await?;
        if cluster_sizes.is_empty() {
            return Ok(vec![]);
        }

        let portion_of_clusters = portion_of_clusters.unwrap_or(DEFAULT_PORTION_OF_CLUSTER);
        let number_of_clusters = DEFAULT_NUMBER_OF_CLUSTER;
        let cluster_ids =
            get_limited_cluster_ids(&cluster_sizes, portion_of_clusters, number_of_clusters);

        Ok(cluster_ids)
    }
}

async fn get_cluster_sizes(
    conn: &mut AsyncPgConnection,
    model_id: i32,
) -> Result<Vec<ClusterSize>, diesel::result::Error> {
    use diesel_async::RunQueryDsl;

    use super::schema::cluster::dsl;

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
