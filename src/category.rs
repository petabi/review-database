use serde::Deserialize;

use super::{tokio_postgres::types::ToSql, Database, Error, OrderDirection, Type};

/// A category for a cluster.
#[derive(Deserialize)]
pub struct Category {
    pub id: i32,
    pub name: String,
}

impl Database {
    /// Adds a new category to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn add_category(&self, name: &str) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.insert_into("category", &[("name", Type::TEXT)], &[&name])
            .await
    }

    /// Returns the number of categories in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn count_categories(&self) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("category", &[], &[], &[]).await
    }

    /// Returns the category with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn load_category(&self, id: i32) -> Result<Category, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from::<Category>(
            "category",
            &["id", "name"],
            &[("id", super::Type::INT4)],
            &[&id],
        )
        .await
    }

    /// Returns the categories between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn load_categories(
        &self,
        after: &Option<(i32, String)>,
        before: &Option<(i32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Category>, Error> {
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
            "category",
            &["id", "name"],
            &[],
            &[],
            &params,
            &("name", Type::TEXT),
            OrderDirection::Asc,
            (after.is_some(), before.is_some()),
            is_first,
            limit,
        )
        .await
    }

    /// Updates the category with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn update_category(&self, id: i32, name: &str) -> Result<(), Error> {
        let conn = self.pool.get().await?;
        conn.update("category", id, &[("name", Type::TEXT)], &[&name])
            .await?;
        Ok(())
    }
}
