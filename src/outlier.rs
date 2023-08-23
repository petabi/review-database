use crate::types::{Source, Timestamp};

use super::{tokio_postgres::types::ToSql, Database, Error, Type};
use serde::{Deserialize, Serialize};

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
}
