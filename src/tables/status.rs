//! The `category` table.
use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{status::Status, Indexable, Indexed, IndexedMap, IndexedTable};

#[allow(dead_code)]
const DEFAULT_ENTRIES: [(u32, &str); 3] = [(1, "reviewed"), (2, "pending review"), (3, "disabled")];

impl<'d> IndexedTable<'d, Status> {
    /// Opens the category table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let table = IndexedMap::new(db, super::CATEGORY)
            .map(IndexedTable::new)
            .ok()?;
        //table.setup().ok()?;
        Some(table)
    }

    /// Inserts a category into the table and returns the ID of the newly added
    /// category.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a category with the same name.
    pub fn insert(&self, description: &str) -> Result<u32> {
        let entry = Status {
            id: u32::MAX,
            description: description.to_string(),
        };
        self.indexed_map.insert(entry)
    }

    /// Update the category name from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> Result<()> {
        let new = Status {
            id: u32::MAX,
            description: new.to_string(),
        };
        let old = Status {
            id: u32::MAX,
            description: old.to_string(),
        };
        self.indexed_map.update(id, &old, &new)
    }

    /// Returns the category with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, id: u32) -> Result<Status> {
        let res = self
            .indexed_map
            .get_by_id(id)
            .and_then(|r| r.ok_or(anyhow::anyhow!("category {id} unavailable")))?;
        let c = super::deserialize(res.as_ref())?;
        Ok(c)
    }

    /// Try adding default entries into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    #[allow(dead_code)]
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

    /// Returns `n` `Category`(ies)
    /// `is_first`: Forward or Reverse order.
    /// `from`: If `from` exists in database then, `bound` is excluded from the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    fn get_n(&self, from: Option<Status>, n: usize, is_first: bool) -> Result<Vec<Status>> {
        use rocksdb::{Direction, IteratorMode};

        let mode = match (&from, is_first) {
            (Some(from), true) => IteratorMode::From(from.indexed_key(), Direction::Forward),
            (Some(from), false) => IteratorMode::From(from.indexed_key(), Direction::Reverse),
            (None, true) => IteratorMode::From(&[0], Direction::Forward),
            (None, false) => IteratorMode::End,
        };

        let mut iter = self
            .indexed_map
            .inner_iterator(mode)?
            .map(|(_, v)| super::deserialize::<Status>(&v))
            .peekable();

        match (from, iter.peek()) {
            (Some(value), Some(Ok(c))) => {
                if value == *c {
                    iter.skip(1).take(n).collect()
                } else {
                    iter.take(n).collect()
                }
            }
            _ => iter.take(n).collect(),
        }
    }

    /// Returns `limit` # of `Category`(ies) according to conditions provided.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_range(
        &self,
        before: Option<Status>,
        after: Option<Status>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Status>> {
        match (before.is_some(), after.is_some()) {
            (true, false) => self.get_n(before, limit, false),
            (false, true) => self.get_n(after, limit, true),
            _ => self.get_n(None, limit, is_first),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{status::Status, Store};

    fn set_up_db() -> (Arc<Store>, Vec<Status>, u32, usize) {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.status_map();

        let mut entries = vec![
            Status {
                id: u32::MAX,
                description: "c".to_string(),
            },
            Status {
                id: u32::MAX,
                description: "a".to_string(),
            },
            Status {
                id: u32::MAX,
                description: "b".to_string(),
            },
            Status {
                id: u32::MAX,
                description: "d".to_string(),
            },
        ];

        for e in entries.iter_mut() {
            let added = table.insert(&e.description).unwrap();
            e.id = added as u32;
        }
        (store, entries, 0, 0)
    }

    #[test]
    fn add() {
        let (store, entries, _offset, counts) = set_up_db();
        let table = store.status_map();

        assert_eq!(table.count().unwrap(), entries.len() + counts);
    }

    #[test]
    fn get() {
        let (store, entries, offset, _counts) = set_up_db();
        let table = store.status_map();

        for (id, entry) in entries.iter().enumerate() {
            assert_eq!(table.get(entry.id).unwrap(), *entry);
            assert_eq!(id + offset as usize, entry.id as usize);
        }
    }

    #[test]
    fn update_for_new_existing_key() {
        let (store, entries, offset, counts) = set_up_db();
        let mut table = store.status_map();

        assert!(table.update(1 + offset, "a", "b").is_err());

        assert_eq!(table.count().unwrap(), entries.len() + counts);
    }

    #[test]
    fn get_range_before() {
        let (store, entries, offset, counts) = set_up_db();

        let table = store.status_map();

        let res = table
            .get_range(
                Some(Status {
                    id: 1 + offset,
                    description: "a".to_string(),
                }),
                None,
                false,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), std::cmp::min(0 + counts, 2));

        let res = table
            .get_range(
                Some(Status {
                    id: 2 + offset,
                    description: "a".to_string(),
                }),
                None,
                false,
                2,
            )
            .unwrap();
        assert_eq!(res.len(), std::cmp::min(1 + counts, 2));
        assert_eq!(res[0], entries[1]);
    }

    #[test]
    fn get_range_after() {
        let (store, entries, offset, _counts) = set_up_db();

        let table = store.status_map();
        let res = table
            .get_range(
                None,
                Some(Status {
                    id: 1 + offset,
                    description: "a".to_string(),
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
                Some(Status {
                    id: 0 + offset,
                    description: "a".to_string(),
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
        let (store, entries, _offset, counts) = set_up_db();

        let table = store.status_map();

        let res = table.get_range(None, None, true, 2 + counts).unwrap();
        assert_eq!(
            res[counts..].iter().collect::<Vec<_>>(),
            vec![&entries[1], &entries[2]]
        );
    }

    #[test]
    fn get_range_last() {
        let (store, entries, offset, _counts) = set_up_db();

        let table = store.status_map();

        let res1 = table.get_range(None, None, false, 2).unwrap();
        let res2 = table
            .get_range(
                Some(Status {
                    id: 5 + offset,
                    description: "x".to_string(),
                }),
                Some(Status {
                    id: 10 + offset,
                    description: "z".to_string(),
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
