use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{Database, Error, schema::cluster::dsl, types::Cluster};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: String,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<crate::types::Id>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Queryable)]
struct ClusterDbSchema {
    id: i32,
    cluster_id: String,
    category_id: i32,
    detector_id: i32,
    event_ids: Vec<Option<i64>>,
    sensors: Vec<Option<String>>,
    labels: Option<Vec<Option<String>>>,
    qualifier_id: i32,
    status_id: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    last_modification_time: Option<NaiveDateTime>,
    model_id: i32,
}

impl From<ClusterDbSchema> for Cluster {
    fn from(c: ClusterDbSchema) -> Self {
        let event_ids: Vec<i64> = c.event_ids.into_iter().flatten().collect();
        let sensors: Vec<String> = c.sensors.into_iter().flatten().collect();
        let labels: Option<Vec<String>> = c
            .labels
            .map(|labels| labels.into_iter().flatten().collect());
        Cluster {
            id: c.id,
            cluster_id: c.cluster_id,
            category_id: c.category_id,
            detector_id: c.detector_id,
            event_ids,
            sensors,
            labels,
            qualifier_id: c.qualifier_id,
            status_id: c.status_id,
            signature: c.signature,
            size: c.size,
            score: c.score,
            last_modification_time: c.last_modification_time,
            model_id: c.model_id,
        }
    }
}

impl Database {
    /// Counts the number of clusters matching the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn count_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
    ) -> Result<i64, Error> {
        let mut query = dsl::cluster.filter(dsl::model_id.eq(&model)).into_boxed();
        if let Some(categories) = categories {
            query = query.filter(dsl::category_id.eq_any(categories));
        }
        if let Some(detectors) = detectors {
            query = query.filter(dsl::detector_id.eq_any(detectors));
        }
        if let Some(qualifiers) = qualifiers {
            query = query.filter(dsl::qualifier_id.eq_any(qualifiers));
        }
        if let Some(statuses) = statuses {
            query = query.filter(dsl::status_id.eq_any(statuses));
        }

        let mut conn = self.pool.get().await?;
        Ok(query.count().get_result(&mut conn).await?)
    }

    /// Returns the clusters that satisfy the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn load_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Cluster>, Error> {
        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::cluster
            .select((
                dsl::id,
                dsl::cluster_id,
                dsl::category_id,
                dsl::detector_id,
                dsl::event_ids,
                dsl::sensors,
                dsl::labels,
                dsl::qualifier_id,
                dsl::status_id,
                dsl::signature,
                dsl::size,
                dsl::score,
                dsl::last_modification_time,
                dsl::model_id,
            ))
            .filter(dsl::model_id.eq(&model))
            .limit(limit)
            .into_boxed();

        if let Some(categories) = categories {
            query = query.filter(dsl::category_id.eq_any(categories));
        }
        if let Some(detectors) = detectors {
            query = query.filter(dsl::detector_id.eq_any(detectors));
        }
        if let Some(qualifiers) = qualifiers {
            query = query.filter(dsl::qualifier_id.eq_any(qualifiers));
        }
        if let Some(statuses) = statuses {
            query = query.filter(dsl::status_id.eq_any(statuses));
        }
        if let Some(after) = after {
            query = query.filter(
                dsl::size
                    .eq(after.1)
                    .and(dsl::id.lt(after.0))
                    .or(dsl::size.lt(after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::size
                    .eq(before.1)
                    .and(dsl::id.gt(before.0))
                    .or(dsl::size.gt(before.1)),
            );
        }
        if is_first {
            query = query
                .order_by(dsl::size.desc())
                .then_order_by(dsl::id.desc());
        } else {
            query = query.order_by(dsl::size.asc()).then_order_by(dsl::id.asc());
        }

        let mut conn = self.pool.get().await?;
        let rows = query.get_results::<ClusterDbSchema>(&mut conn).await?;
        if is_first {
            Ok(rows.into_iter().map(Into::into).collect())
        } else {
            Ok(rows.into_iter().rev().map(Into::into).collect())
        }
    }

    /// Updates the cluster with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn update_cluster(
        &self,
        id: i32,
        category: Option<i32>,
        qualifier: Option<i32>,
        status: Option<i32>,
    ) -> Result<(), Error> {
        if category.is_none() && qualifier.is_none() && status.is_none() {
            return Err(Error::InvalidInput("no column to update".to_string()));
        }

        let mut conn = self.pool.get().await?;
        let (category_id, qualifier_id, status_id) = dsl::cluster
            .select((dsl::category_id, dsl::qualifier_id, dsl::status_id))
            .filter(dsl::id.eq(id))
            .get_result(&mut conn)
            .await?;
        let category_id = category.unwrap_or(category_id);
        let qualifier_id = qualifier.unwrap_or(qualifier_id);
        let status_id = status.unwrap_or(status_id);
        diesel::update(dsl::cluster.filter(dsl::id.eq(id)))
            .set((
                dsl::category_id.eq(category_id),
                dsl::qualifier_id.eq(qualifier_id),
                dsl::status_id.eq(status_id),
            ))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    /// Updates the clusters with the given cluster IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn update_clusters(
        &self,
        cluster_update: Vec<UpdateClusterRequest>,
        model_id: i32,
    ) -> Result<(), Error> {
        // Execute 1,000 UPSERT operations per transaction
        let mut chunks: Vec<Vec<UpdateClusterRequest>> =
            Vec::with_capacity(cluster_update.len() / 1_000 + 1);
        let mut peekable = cluster_update.into_iter().peekable();
        while peekable.peek().is_some() {
            chunks.push(peekable.by_ref().take(1_000).collect::<Vec<_>>());
        }

        let mut tasks = tokio::task::JoinSet::new();

        for chunk in chunks {
            let pool = self.pool.clone();
            tasks.spawn(async move {
                let mut conn = pool.get().await?;
                conn.build_transaction()
                    .run(move |conn| {
                        Box::pin(async move {
                            for c in chunk {
                                upsert(conn, c, model_id).await?;
                            }
                            Ok::<_, Error>(())
                        })
                    })
                    .await?;
                anyhow::Ok(())
            });
        }

        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(Err(e)) => {
                    error!("An error occurred while updating clusters: {e:#}");
                }
                Err(e) => error!("Failed to execute cluster update: {e:#}"),
                _ => {}
            }
        }

        Ok(())
    }

    /// Find the numerical ids according to string ids of clusters for a model
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn cluster_name_to_ids(
        &self,
        model_id: i32,
        names: &[&str],
    ) -> Result<Vec<(i32, String)>, Error> {
        let query = dsl::cluster
            .select((dsl::id, dsl::cluster_id))
            .filter(dsl::model_id.eq(&model_id))
            .filter(dsl::cluster_id.eq_any(names));
        let mut conn = self.pool.get().await?;
        Ok(query.get_results(&mut conn).await?)
    }
}

async fn upsert(
    conn: &mut AsyncPgConnection,
    cluster: UpdateClusterRequest,
    model_id: i32,
) -> Result<usize, diesel::result::Error> {
    use diesel::sql_types::{Array, BigInt, Double, Integer, Nullable, Text};

    let query = "SELECT attempt_cluster_upsert(
        $1::text, $2::int4, $3::int8[], $4::text[], $5::int4, $6::text, $7::int8, $8::int4, $9::text[], $10::float8)";
    let (timestamps, sensors) =
        cluster
            .event_ids
            .iter()
            .fold((Vec::new(), Vec::new()), |(mut ts, mut src), id| {
                ts.push(&id.0);
                src.push(&id.1);
                (ts, src)
            });

    diesel::sql_query(query)
        .bind::<Text, _>(&cluster.cluster_id)
        .bind::<Integer, _>(&cluster.detector_id)
        .bind::<Array<BigInt>, _>(&timestamps)
        .bind::<Array<Text>, _>(&sensors)
        .bind::<Integer, _>(&model_id)
        .bind::<Text, _>(&cluster.signature)
        .bind::<BigInt, _>(&cluster.size)
        .bind::<Integer, _>(&cluster.status_id)
        .bind::<Nullable<Array<Text>>, _>(&cluster.labels)
        .bind::<Nullable<Double>, _>(&cluster.score)
        .execute(conn)
        .await
}
