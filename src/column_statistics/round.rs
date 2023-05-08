use crate::{
    schema::{cluster::dsl as cl_dsl, event_range::dsl},
    Database, Error, Type,
};
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde::Deserialize;

#[derive(Deserialize, Queryable)]
#[allow(clippy::module_name_repetitions)]
pub struct RoundByCluster {
    pub id: i32,
    pub time: NaiveDateTime,
    pub first_event_id: i64,
    pub last_event_id: i64,
}

#[derive(Deserialize, Queryable)]
#[allow(clippy::module_name_repetitions)]
pub struct RoundByModel {
    pub id: i32,
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
        after: &Option<(i32, NaiveDateTime)>,
        before: &Option<(i32, NaiveDateTime)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<RoundByCluster>, Error> {
        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::event_range
            .select((dsl::id, dsl::time, dsl::first_event_id, dsl::last_event_id))
            .filter(dsl::cluster_id.eq(&cluster_id))
            .limit(limit)
            .into_boxed();

        if let Some(after) = after {
            query = query.filter(
                dsl::time
                    .eq(after.1)
                    .and(dsl::id.gt(after.0))
                    .or(dsl::time.gt(after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::time
                    .eq(before.1)
                    .and(dsl::id.lt(before.0))
                    .or(dsl::time.lt(before.1)),
            );
        }
        if is_first {
            query = query.order_by(dsl::time.asc()).then_order_by(dsl::id.asc());
        } else {
            query = query
                .order_by(dsl::time.desc())
                .then_order_by(dsl::id.desc());
        }

        let mut conn = self.pool.get_diesel_conn().await?;
        let mut rows: Vec<RoundByCluster> = query.get_results(&mut conn).await?;
        if !is_first {
            rows = rows.into_iter().rev().collect();
        }
        Ok(rows)
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
        let mut conn = self.pool.get_diesel_conn().await?;
        let cluster_id = cl_dsl::cluster
            .select(cl_dsl::id)
            .filter(cl_dsl::model_id.eq(&model_id))
            .first::<i32>(&mut conn)
            .await?;
        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::event_range
            .select((dsl::id, dsl::time))
            .filter(dsl::cluster_id.eq(&cluster_id))
            .limit(limit)
            .into_boxed();

        if let Some(after) = after {
            query = query.filter(
                dsl::time
                    .eq(after.1)
                    .and(dsl::id.gt(after.0))
                    .or(dsl::time.gt(after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::time
                    .eq(before.1)
                    .and(dsl::id.lt(before.0))
                    .or(dsl::time.lt(before.1)),
            );
        }
        if is_first {
            query = query.order_by(dsl::time.asc()).then_order_by(dsl::id.asc());
        } else {
            query = query
                .order_by(dsl::time.desc())
                .then_order_by(dsl::id.desc());
        }

        let mut rows: Vec<RoundByModel> = query.get_results(&mut conn).await?;
        if !is_first {
            rows = rows.into_iter().rev().collect();
        }
        Ok(rows)
    }
}
