use crate::{tokio_postgres::types::ToSql, Database, Error, OrderDirection, Type};
use chrono::{naive::serde::ts_nanoseconds, NaiveDateTime};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RoundByCluster {
    pub id: i32,
    #[serde(with = "ts_nanoseconds")]
    pub time: NaiveDateTime,
    pub first_event_id: i64,
    pub last_event_id: i64,
}

#[derive(Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RoundByModel {
    pub id: i32,
    #[serde(with = "ts_nanoseconds")]
    pub time: NaiveDateTime,
}

impl Database {
    /// Returns the number of rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn count_rounds_by_cluster(&self, cluster_id: i32) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count(
            "event_range",
            &[("cluster_id", Type::INT4)],
            &[],
            &[&cluster_id],
        )
        .await
    }

    /// Returns the number of rounds in the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn count_rounds_by_model(&self, model_id: i32) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        let cluster_id: i32 = conn
            .select_one_from(
                "cluster",
                &["id"],
                &[("model_id", Type::INT4)],
                &[&model_id],
            )
            .await?;

        conn.count(
            "event_range",
            &[("cluster_id", Type::INT4)],
            &[],
            &[&cluster_id],
        )
        .await
    }

    /// Returns the rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn load_rounds_by_cluster(
        &self,
        cluster_id: i32,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<RoundByCluster>, Error> {
        let conn = self.pool.get().await?;
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&cluster_id];
        if let Some(cursor) = after {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        if let Some(cursor) = before {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        conn.select_slice(
            "event_range",
            &["id", "time", "first_event_id", "last_event_id"],
            &[("cluster_id", Type::INT4)],
            &[],
            &params,
            &("event_range.time", Type::TIMESTAMP),
            OrderDirection::Asc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }

    /// Returns the rounds in the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn load_rounds_by_model(
        &self,
        model_id: i32,
        after: &Option<(i32, NaiveDateTime)>,
        before: &Option<(i32, NaiveDateTime)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<RoundByModel>, Error> {
        let conn = self.pool.get().await?;
        let cluster_id: i32 = conn
            .select_one_from(
                "cluster",
                &["id"],
                &[("model_id", Type::INT4)],
                &[&model_id],
            )
            .await?;
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&cluster_id];
        if let Some(cursor) = after {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        if let Some(cursor) = before {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        conn.select_slice(
            "event_range",
            &["id", "time"],
            &[("cluster_id", Type::INT4)],
            &[],
            &params,
            &("event_range.time", Type::TIMESTAMP),
            OrderDirection::Asc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }
}
