use crate::{
    tokio_postgres::types::ToSql, types::Cluster, Database, Error, OrderDirection, Type, Value,
};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::error;

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

    /// Returns the numerical ID of the cluster with the given cluster ID.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn cluster_id(&self, cluster_id: &str, model_id: i32) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from(
            "cluster",
            &["id"],
            &[("cluster_id", Type::TEXT), ("model_id", Type::INT4)],
            &[&cluster_id, &model_id],
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
        let conn = self.pool.get().await?;
        let mut any_variables = Vec::new();
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&model];
        if categories.is_some() {
            any_variables.push(("category_id", Type::INT4_ARRAY));
            params.push(&categories);
        }
        if detectors.is_some() {
            any_variables.push(("detector_id", Type::INT4_ARRAY));
            params.push(&detectors);
        }
        if qualifiers.is_some() {
            any_variables.push(("qualifier_id", Type::INT4_ARRAY));
            params.push(&qualifiers);
        }
        if statuses.is_some() {
            any_variables.push(("status_id", Type::INT4_ARRAY));
            params.push(&statuses);
        }
        if let Some(cursor) = after {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        if let Some(cursor) = before {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        conn.select_slice(
            "cluster",
            &[
                "id",
                "cluster_id",
                "category_id",
                "detector_id",
                "event_ids",
                "event_sources",
                "labels",
                "qualifier_id",
                "status_id",
                "signature",
                "size",
                "score",
                "last_modification_time",
                "model_id",
            ],
            &[("model_id", Type::INT4)],
            &any_variables,
            &params,
            &("size", Type::INT8),
            OrderDirection::Desc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }

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
