use serde::Deserialize;

use super::{tokio_postgres::types::ToSql, Database, Error, OrderDirection, Type};

#[derive(Deserialize)]
pub struct Qualifier {
    pub id: i32,
    pub description: String,
}

impl Database {
    /// Adds a new qualifier to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn add_qualifier(&self, description: &str) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.insert_into("qualifier", &[("description", Type::TEXT)], &[&description])
            .await
    }

    /// Counts the number of qualifiers in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn count_qualifiers(&self) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("qualifier", &[], &[], &[]).await
    }

    /// Returns the qualifier with the given id.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_qualifier(&self, id: i32) -> Result<Qualifier, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from::<Qualifier>(
            "qualifier",
            &["id", "description"],
            &[("id", super::Type::INT4)],
            &[&id],
        )
        .await
    }

    /// Returns a list of qualifiers between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn load_qualifiers(
        &self,
        after: &Option<(i32, String)>,
        before: &Option<(i32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Qualifier>, Error> {
        let conn = self.pool.get().await?;
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        if let Some(cursor) = after {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        if let Some(cursor) = before {
            params.push(&cursor.1);
            params.push(&cursor.0);
        }
        conn.select_slice(
            "qualifier",
            &["id", "description"],
            &[],
            &[],
            &params,
            &("description", Type::TEXT),
            OrderDirection::Asc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }

    /// Updates the description of the qualifier with the given id.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub async fn update_qualifier(&self, id: i32, description: &str) -> Result<(), Error> {
        let conn = self.pool.get().await?;
        conn.update(
            "qualifier",
            id,
            &[("description", Type::TEXT)],
            &[&description],
        )
        .await?;
        Ok(())
    }
}
