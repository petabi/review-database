use serde::Deserialize;

use super::{Database, Error, Type};

#[derive(Deserialize, Queryable)]
pub struct Status {
    pub id: i32,
    pub description: String,
}

impl Database {
    /// Adds a new status to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn add_status(&self, description: &str) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.insert_into("status", &[("description", Type::TEXT)], &[&description])
            .await
    }

    /// Counts the number of statuses in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn count_statuses(&self) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("status", &[], &[], &[]).await
    }

    /// Returns the status with the given id.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_status(&self, id: i32) -> Result<Status, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from::<Status>(
            "status",
            &["id", "description"],
            &[("id", super::Type::INT4)],
            &[&id],
        )
        .await
    }

    /// Returns a list of statuses between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_statuses(
        &self,
        after: &Option<(i32, String)>,
        before: &Option<(i32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Status>, Error> {
        use super::schema::status::dsl;
        use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::status
            .select((dsl::id, dsl::description))
            .limit(limit)
            .into_boxed();

        if let Some(after) = after {
            query = query.filter(
                dsl::description
                    .eq(&after.1)
                    .and(dsl::id.gt(after.0))
                    .or(dsl::description.gt(&after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::description
                    .eq(&before.1)
                    .and(dsl::id.lt(before.0))
                    .or(dsl::description.lt(&before.1)),
            );
        }
        if is_first {
            query = query
                .order_by(dsl::description.asc())
                .then_order_by(dsl::id.asc());
        } else {
            query = query
                .order_by(dsl::description.desc())
                .then_order_by(dsl::id.desc());
        }

        let mut conn = self.pool.get_diesel_conn().await?;
        let mut rows: Vec<Status> = query.get_results(&mut conn).await?;
        if !is_first {
            rows = rows.into_iter().rev().collect();
        }
        Ok(rows)
    }

    /// Updates the status with the given id.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn update_status(&self, id: i32, description: &str) -> Result<(), Error> {
        let conn = self.pool.get().await?;
        conn.update(
            "status",
            id,
            &[("description", Type::TEXT)],
            &[&description],
        )
        .await?;
        Ok(())
    }
}
