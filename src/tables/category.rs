//! The `category` table.
use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{category::Category, Indexed, IndexedMap, IndexedTable};

const DEFAULT_ENTRIES: [(u32, &str); 2] = [(1, "Non-Specified Alert"), (2, "Irrelevant Alert")];

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

    /// Try adding default entries into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    fn setup(&self) -> Result<()> {
        if self.indexed_map.count()? > 0 {
            return Ok(());
        }
        let added = self.add("dummy")?;
        if added != 0 {
            self.remove(added)?; // so that `added` could be re-used as id.
            return Ok(());
        }
        self.deactivate(added)?; // 0 is deactivated as id for `category`.

        for (id, name) in DEFAULT_ENTRIES {
            let added = self.add(name)?;
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
            let added = table.add(&e.name).unwrap();
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

    #[test]
    fn get_range_before() {
        let (store, entries) = set_up_db();

        let table = store.category_map();

        let res = table
            .get_range(
                Some(Category {
                    id: 1 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "a".to_string(),
                }),
                None,
                false,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), std::cmp::min(0 + DEFAULT_ENTRIES.len(), 2));

        let res = table
            .get_range(
                Some(Category {
                    id: 2 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "a".to_string(),
                }),
                None,
                false,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), std::cmp::min(1 + DEFAULT_ENTRIES.len(), 2));
        assert_eq!(res[0], entries[1]);
    }

    #[test]
    fn get_range_after() {
        let (store, entries) = set_up_db();

        let table = store.category_map();
        let res = table
            .get_range(
                None,
                Some(Category {
                    id: 1 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "a".to_string(),
                }),
                true,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], entries[2]);
        assert_eq!(res[1], entries[0]);

        let res = table
            .get_range(
                None,
                Some(Category {
                    id: 0 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "a".to_string(),
                }),
                true,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], entries[1]);
        assert_eq!(res[1], entries[2]);
    }

    #[test]
    fn get_range_first() {
        let (store, entries) = set_up_db();

        let table = store.category_map();

        let res = table.get_range(None, None, true, 4).unwrap();
        assert_eq!(
            res[2..].iter().collect::<Vec<_>>(),
            vec![&entries[1], &entries[2]]
        );
    }

    #[test]
    fn get_range_last() {
        let (store, entries) = set_up_db();

        let table = store.category_map();

        let res1 = table.get_range(None, None, false, 2).unwrap();
        let res2 = table
            .get_range(
                Some(Category {
                    id: 5 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "x".to_string(),
                }),
                Some(Category {
                    id: 10 + DEFAULT_ENTRIES.len() as u32 + 1,
                    name: "z".to_string(),
                }),
                false,
                2,
            )
            .unwrap();

        assert_eq!(res1, res2);
        assert_eq!(
            res1.iter().collect::<Vec<_>>(),
            vec![&entries[3], &entries[0]]
        );
    }
}
