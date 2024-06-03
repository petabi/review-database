use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::error;

use super::{tokio_postgres::types::ToSql, Database, Error, Type};
use crate::types::{Outlier, Source, Timestamp};

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateOutlierRequest {
    pub is_new_outlier: bool,
    pub raw_event: Vec<u8>,
    pub event_ids: Vec<crate::types::Id>,
    pub size: i64,
}

#[derive(Queryable)]
struct OutlierDbSchema {
    id: i32,
    raw_event: Vec<u8>,
    event_ids: Vec<Option<i64>>,
    event_sources: Vec<Option<Source>>,
    size: i64,
    model_id: i32,
}

impl From<OutlierDbSchema> for Outlier {
    fn from(o: OutlierDbSchema) -> Self {
        let event_ids: Vec<i64> = o.event_ids.into_iter().flatten().collect();
        let event_sources: Vec<Source> = o.event_sources.into_iter().flatten().collect();
        Outlier {
            id: o.id,
            raw_event: o.raw_event,
            event_ids,
            event_sources,
            size: o.size,
            model_id: o.model_id,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct LoadOutlier {
    #[serde(with = "serde_bytes")]
    raw_event: Vec<u8>,
    event_ids: Vec<crate::types::Id>,
}

impl Database {
    /// Returns the number of outliers for the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn count_outliers(&self, model: i32) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("outlier", &[("model_id", Type::INT4)], &[], &[&model])
            .await
    }

    /// Deletes the outliers with the given IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn delete_outliers(
        &self,
        event_ids: Vec<crate::types::Id>,
        model_id: i32,
    ) -> Result<(), Error> {
        let (timestamps, sources) =
            event_ids
                .into_iter()
                .fold((vec![], vec![]), |(mut ts, mut src), e| {
                    let (t, s) = e;
                    ts.push(t);
                    src.push(s);
                    (ts, src)
                });
        let param: Vec<&(dyn ToSql + Sync)> = vec![&timestamps, &sources, &model_id];
        let conn = self.pool.get().await?;
        conn.execute_function(
            "attempt_outlier_delete",
            &[Type::INT8_ARRAY, Type::TEXT_ARRAY, Type::INT4],
            param.as_slice(),
        )
        .await?;
        Ok(())
    }

    /// Returns a list of outliers between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_outliers(
        &self,
        model: i32,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Outlier>, Error> {
        use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        use super::schema::outlier::dsl;

        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::outlier
            .select((
                dsl::id,
                dsl::raw_event,
                dsl::event_ids,
                dsl::event_sources,
                dsl::size,
                dsl::model_id,
            ))
            .filter(dsl::model_id.eq(&model))
            .limit(limit)
            .into_boxed();

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
        let rows = query.get_results::<OutlierDbSchema>(&mut conn).await?;
        if is_first {
            Ok(rows.into_iter().map(Into::into).collect())
        } else {
            Ok(rows.into_iter().rev().map(Into::into).collect())
        }
    }

    /// Returns all outliers for the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_all_outliers_by_model_id(
        &self,
        model_id: i32,
    ) -> Result<Vec<LoadOutlier>, Error> {
        #[derive(Deserialize, Serialize)]
        struct OutlierRow {
            #[serde(with = "serde_bytes")]
            raw_event: Vec<u8>,
            event_ids: Vec<Timestamp>,
            event_sources: Vec<Source>,
        }

        let conn = self.pool.get().await?;
        let results = conn
            .select_in::<OutlierRow>(
                "outlier",
                &["raw_event", "event_ids", "event_sources"],
                &[("model_id", Type::INT4)],
                &[],
                &[],
                &[&model_id],
            )
            .await?;
        Ok(results
            .into_iter()
            .map(|outlier| {
                let (raw_event, timestamps, sources) =
                    (outlier.raw_event, outlier.event_ids, outlier.event_sources);
                let event_ids = timestamps.into_iter().zip(sources.into_iter()).collect();
                LoadOutlier {
                    raw_event,
                    event_ids,
                }
            })
            .collect())
    }

    /// Updates the outliers with the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn update_outliers(
        &self,
        outlier_update: Vec<UpdateOutlierRequest>,
        model_id: i32,
    ) -> Result<(), Error> {
        let query =
            "SELECT attempt_outlier_upsert($1::bool, $2::bytea, $3::int4, $4::int8[], $5::text[], $6::int8)";

        // Split `outlier_update` into Vector of 1,000 each to create database
        // transactions with 1,000 queries
        let mut chunks: Vec<Vec<UpdateOutlierRequest>> =
            Vec::with_capacity(outlier_update.len() / 1_000 + 1);
        let mut peekable = outlier_update.into_iter().peekable();
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
                                &c.is_new_outlier,
                                &c.raw_event,
                                &model_id,
                                &timestamps,
                                &sources,
                                &c.size,
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
                            error!("An error occurred while updating outliers: {:#}", e);
                        }
                        Err(e) => error!("Failed to execute outlier update: {:#}", e),
                        _ => {}
                    }
                }),
        )
        .await;

        Ok(())
    }
}
