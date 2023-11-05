use crate::{
    schema::{cluster::dsl as c_d, column_description::dsl as cd_d},
    Database, Error,
};
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde::Deserialize;

#[derive(Deserialize, Queryable)]
#[allow(clippy::module_name_repetitions)]
pub struct Round {
    pub id: i32,
    pub batch_ts: NaiveDateTime,
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
        use diesel::dsl::count_distinct;
        let mut conn = self.pool.get_diesel_conn().await?;
        Ok(cd_d::column_description
            .select(count_distinct(cd_d::batch_ts))
            .filter(cd_d::cluster_id.eq(cluster_id))
            .first(&mut conn)
            .await?)
    }

    /// Returns the rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn load_rounds_by_cluster(
        &self,
        cluster_id: i32,
        after: &Option<NaiveDateTime>,
        before: &Option<NaiveDateTime>,
        is_first: bool,
        limit: usize,
    ) -> Result<(i32, Vec<NaiveDateTime>), Error> {
        let mut conn = self.pool.get_diesel_conn().await?;
        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let model_id = c_d::cluster
            .select(c_d::model_id)
            .filter(c_d::id.eq(cluster_id))
            .first(&mut conn)
            .await?;

        let mut query = cd_d::column_description
            .select(cd_d::batch_ts)
            .distinct()
            .filter(cd_d::cluster_id.eq(cluster_id))
            .into_boxed();

        if let Some(after) = after {
            query = query.filter(cd_d::batch_ts.eq(after).or(cd_d::batch_ts.gt(after)));
        }
        if let Some(before) = before {
            query = query.filter(cd_d::batch_ts.eq(before).or(cd_d::batch_ts.lt(before)));
        }

        if is_first {
            query = query.order_by(cd_d::batch_ts.asc()).limit(limit);
        } else {
            query = query.order_by(cd_d::batch_ts.desc()).limit(limit);
        }

        let rounds: Vec<NaiveDateTime> = query.get_results(&mut conn).await?;

        Ok((model_id, rounds))
    }
}
