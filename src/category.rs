use serde::{Deserialize, Serialize};

use crate::{Indexable, IndexedMapUpdate};

use super::{Database, Error, Type};

/// A category for a cluster.
#[derive(Deserialize, Queryable, Serialize)]
pub struct Category {
    pub id: u32,
    pub name: String,
}

impl Indexable for Category {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn value(&self) -> Vec<u8> {
        use bincode::Options;

        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

impl IndexedMapUpdate for Category {
    type Entry = Category;

    fn key(&self) -> Option<&[u8]> {
        if self.name.is_empty() {
            None
        } else {
            Some(self.name.as_bytes())
        }
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.name == value.name
    }
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
    // pub async fn load_categories(
    //     &self,
    //     after: &Option<(i32, String)>,
    //     before: &Option<(i32, String)>,
    //     is_first: bool,
    //     limit: usize,
    // ) -> Result<Vec<Category>, Error> {
    //     use super::schema::category::dsl;
    //     use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
    //     use diesel_async::RunQueryDsl;

    //     let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
    //     let mut query = dsl::category
    //         .select((dsl::id, dsl::name))
    //         .limit(limit)
    //         .into_boxed();

    //     if let Some(after) = after {
    //         query = query.filter(
    //             dsl::name
    //                 .eq(&after.1)
    //                 .and(dsl::id.gt(after.0))
    //                 .or(dsl::name.gt(&after.1)),
    //         );
    //     }
    //     if let Some(before) = before {
    //         query = query.filter(
    //             dsl::name
    //                 .eq(&before.1)
    //                 .and(dsl::id.lt(before.0))
    //                 .or(dsl::name.lt(&before.1)),
    //         );
    //     }
    //     if is_first {
    //         query = query.order_by(dsl::name.asc()).then_order_by(dsl::id.asc());
    //     } else {
    //         query = query
    //             .order_by(dsl::name.desc())
    //             .then_order_by(dsl::id.desc());
    //     }

    //     let mut conn = self.pool.get_diesel_conn().await?;
    //     let mut rows: Vec<Category> = query.get_results(&mut conn).await?;
    //     if !is_first {
    //         rows = rows.into_iter().rev().collect();
    //     }
    //     Ok(rows)
    // }

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
