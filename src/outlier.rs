use crate::types::{Source, Timestamp};

use super::{tokio_postgres::types::ToSql, Database, Error, OrderDirection, Type};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateOutlierRequest {
    pub is_new_outlier: bool,
    pub raw_event: Vec<u8>,
    pub event_ids: Vec<crate::types::Id>,
    pub size: i64,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, Serialize)]
pub struct OutlierInfo {
    pub id: i64,
    pub rank: i64,
    pub distance: f64,
    pub source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct LoadOutlier {
    #[serde(with = "serde_bytes")]
    raw_event: Vec<u8>,
    event_ids: Vec<crate::types::Id>,
}

impl Database {
    pub async fn count_outliers(&self, model: i32) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("outlier", &[("model_id", Type::INT4)], &[], &[&model])
            .await
    }

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

    pub async fn load_outliers(
        &self,
        model: i32,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<super::types::Outlier>, Error> {
        let conn = self.pool.get().await?;
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&model];
        if let Some(cursor) = after {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        if let Some(cursor) = before {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        conn.select_slice(
            "outlier",
            &[
                "id",
                "raw_event",
                "event_ids",
                "event_sources",
                "size",
                "model_id",
            ],
            &[("model_id", Type::INT4)],
            &[],
            &params,
            &("size", Type::INT8),
            OrderDirection::Desc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }

    pub async fn load_all_outliers_by_model_id(
        &self,
        model_id: i32,
    ) -> Result<Vec<LoadOutlier>, Error> {
        let conn = self.pool.get().await?;

        #[derive(Deserialize, Serialize)]
        struct OutlierRow {
            #[serde(with = "serde_bytes")]
            raw_event: Vec<u8>,
            event_ids: Vec<Timestamp>,
            event_sources: Vec<Source>,
        }

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
