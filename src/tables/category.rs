//! The `category` table.
use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{category::Category, types::FromKeyValue, Indexed, IndexedMap, IndexedTable};

const DEFAULT_ENTRIES: [(u32, &str); 2] = [(1, "Non-Specified Alert"), (2, "Irrelevant Alert")];

impl FromKeyValue for Category {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl<'d> IndexedTable<'d, Category> {
    /// Opens the category table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let table = IndexedMap::new(db, super::CATEGORY)
            .map(IndexedTable::new)
            .ok()?;
        table.setup().ok()?;
        Some(table)
    }

    /// Inserts a category into the table and returns the ID of the newly added
    /// category.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a category with the same name.
    pub fn insert(&self, name: &str) -> Result<u32> {
        let entry = Category {
            id: u32::MAX,
            name: name.to_string(),
        };
        self.indexed_map.insert(entry)
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

    /// Returns the category with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, id: u32) -> Result<Category> {
        self.indexed_map
            .get_by_id(id)
            .map(|entry| entry.ok_or(anyhow::anyhow!("category {id} unavailable")))?
    }

    /// Try adding default entries into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    fn setup(&self) -> Result<()> {
        if self.indexed_map.count()? > 0 {
            return Ok(());
        }
        let added = self.insert("dummy")?;
        if added != 0 {
            self.remove(added)?; // so that `added` could be re-used as id.
            return Ok(());
        }
        self.deactivate(added)?; // 0 is deactivated as id for `category`.

        for (id, name) in DEFAULT_ENTRIES {
            let added = self.insert(name)?;
            if added != id {
                self.remove(added)?; // so that `added` could be re-used as id.
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{category::Category, tables::category::DEFAULT_ENTRIES, Store};

    fn set_up_db() -> (Arc<Store>, Vec<Category>) {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.category_map();

        let mut entries = vec![
            Category {
                id: u32::MAX,
                name: "c".to_string(),
            },
            Category {
                id: u32::MAX,
                name: "a".to_string(),
            },
            Category {
                id: u32::MAX,
                name: "b".to_string(),
            },
            Category {
                id: u32::MAX,
                name: "d".to_string(),
            },
        ];

        for e in entries.iter_mut() {
            let added = table.insert(&e.name).unwrap();
            e.id = added as u32;
        }
        (store, entries)
    }

    #[test]
    fn add() {
        let (store, entries) = set_up_db();
        let table = store.category_map();

        assert_eq!(
            table.count().unwrap(),
            entries.len() + super::DEFAULT_ENTRIES.len()
        );
    }

    #[test]
    fn get() {
        let (store, entries) = set_up_db();
        let table = store.category_map();

        for (id, entry) in entries.iter().enumerate() {
            assert_eq!(table.get(entry.id).unwrap(), *entry);
            assert_eq!(id + DEFAULT_ENTRIES.len() + 1, entry.id as usize);
        }
    }

    #[test]
    fn update_for_new_existing_key() {
        let (store, entries) = set_up_db();
        let mut table = store.category_map();

        assert!(table
            .update(1 + DEFAULT_ENTRIES.len() as u32 + 1, "a", "b")
            .is_err());

        assert_eq!(
            table.count().unwrap(),
            entries.len() + DEFAULT_ENTRIES.len()
        );
    }
}
