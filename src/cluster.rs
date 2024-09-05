use chrono::NaiveDateTime;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{tokio_postgres::types::ToSql, types::Cluster, Database, Error, Type, Value};

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
    event_sources: Vec<Option<String>>,
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
        let event_sources: Vec<String> = c.event_sources.into_iter().flatten().collect();
        let labels: Option<Vec<String>> = c
            .labels
            .map(|labels| labels.into_iter().flatten().collect());
        Cluster {
            id: c.id,
            cluster_id: c.cluster_id,
            category_id: c.category_id,
            detector_id: c.detector_id,
            event_ids,
            event_sources,
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
    #[allow(clippy::vec_init_then_push)] // `vec![..]` requires static lifetime.
    pub async fn count_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
    ) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        let mut any_variables = Vec::new();
        let mut values = Vec::<&Value>::new();
        values.push(&model);
        if categories.is_some() {
            any_variables.push(("category_id", Type::INT4_ARRAY));
            values.push(&categories);
        }
        if detectors.is_some() {
            any_variables.push(("detector_id", Type::INT4_ARRAY));
            values.push(&detectors);
        }
        if qualifiers.is_some() {
            any_variables.push(("qualifier_id", Type::INT4_ARRAY));
            values.push(&qualifiers);
        }
        if statuses.is_some() {
            any_variables.push(("status_id", Type::INT4_ARRAY));
            values.push(&statuses);
        }
        conn.count(
            "cluster",
            &[("model_id", Type::INT4)],
            &any_variables,
            &values,
        )
        .await
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
        use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        use super::schema::cluster::dsl;

        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::cluster
            .select((
                dsl::id,
                dsl::cluster_id,
                dsl::category_id,
                dsl::detector_id,
                dsl::event_ids,
                dsl::event_sources,
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

        let mut conn = self.pool.get_diesel_conn().await?;
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
        let mut columns = Vec::new();
        let mut values = Vec::<&Value>::new();
        if category.is_some() {
            columns.push(("category_id", Type::INT4));
            values.push(&category);
        }
        if qualifier.is_some() {
            columns.push(("qualifier_id", Type::INT4));
            values.push(&qualifier);
        }
        if status.is_some() {
            columns.push(("status_id", Type::INT4));
            values.push(&status);
        }

        if columns.is_empty() {
            Err(Error::InvalidInput("no column to update".to_string()))
        } else {
            let conn = self.pool.get().await?;
            conn.update("cluster", id, &columns, &values).await?;
            Ok(())
        }
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
        let query = "SELECT attempt_cluster_upsert(
            $1::text, $2::int4, $3::int8[], $4::text[], $5::int4, $6::text, $7::int8, $8::int4, $9::text[], $10::float8)";

        // Split `cluster_update` into Vector of 1,000 each to create database
        // transactions with 1,000 queries
        let mut chunks: Vec<Vec<UpdateClusterRequest>> =
            Vec::with_capacity(cluster_update.len() / 1_000 + 1);
        let mut peekable = cluster_update.into_iter().peekable();
        while peekable.peek().is_some() {
            chunks.push(peekable.by_ref().take(1_000).collect::<Vec<_>>());
        }

        join_all(
            chunks
                .into_iter()
                .map(|chunk| {
                    let pool = self.pool.clone();
                    tokio::spawn(async move {
                        let mut conn = pool.get().await?;
                        let txn = conn.build_transaction().await?;
                        for c in chunk {
                            let (timestamps, sources) = c.event_ids.iter().fold(
                                (Vec::new(), Vec::new()),
                                |(mut ts, mut src), id| {
                                    ts.push(&id.0);
                                    src.push(&id.1);
                                    (ts, src)
                                },
                            );
                            let params: Vec<&(dyn ToSql + Sync)> = vec![
                                &c.cluster_id,
                                &c.detector_id,
                                &timestamps,
                                &sources,
                                &model_id,
                                &c.signature,
                                &c.size,
                                &c.status_id,
                                &c.labels,
                                &c.score,
                            ];

                            txn.execute(query, params.as_slice()).await?;
                        }
                        txn.commit().await?;
                        anyhow::Ok(())
                    })
                })
                .map(|task| async move {
                    match task.await {
                        Ok(Err(e)) => {
                            error!("An error occurred while updating clusters: {:#}", e);
                        }
                        Err(e) => error!("Failed to execute cluster update: {:#}", e),
                        _ => {}
                    }
                }),
        )
        .await;

        Ok(())
    }
}
