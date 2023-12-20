//! The `batch_info` table.
use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{category::Category, Indexed, IndexedMap, IndexedTable};

impl<'d> IndexedTable<'d, Category> {
    /// Opens the category table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::CATEGORY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Add a category entry with `name`
    ///
    /// Returns the `ID` of the newly added category
    ///
    /// # Errors
    ///
    /// Returns an error if the `name` already exists.
    pub fn add(&self, name: &str) -> Result<u32> {
        let entry = Category {
            id: u32::MAX,
            name: name.to_string(),
        };
        self.insert(entry)
    }

    /// Update the category name from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> Result<()> {
        let new = Category {
            id,
            name: new.to_string(),
        };
        let old = Category {
            id,
            name: old.to_string(),
        };
        self.indexed_map.update(id, &old, &new)
    }
}
