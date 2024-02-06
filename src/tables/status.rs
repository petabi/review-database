//! The `status` table.
use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{types::Status, Indexable, Indexed, IndexedMap, IndexedMapUpdate, IndexedTable};

// The following will be used when PostgreSQL status table is deleted
const DEFAULT_ENTRIES: [(u32, &str); 3] = [(1, "reviewed"), (2, "pending review"), (3, "disabled")];

impl Indexable for Status {
    fn key(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.description.as_bytes())
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

impl IndexedMapUpdate for Status {
    type Entry = Status;

    fn key(&self) -> Option<Cow<[u8]>> {
        if self.description.is_empty() {
            None
        } else {
            Some(Cow::Borrowed(self.description.as_bytes()))
        }
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.description.clear();
        value.description.push_str(&self.description);

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.description == value.description
    }
}

impl<'d> IndexedTable<'d, Status> {
    /// Opens the status table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let table = IndexedMap::new(db, super::STATUSES)
            .map(IndexedTable::new)
            .ok()?;
        table.setup().ok()?;
        Some(table)
    }

    /// Inserts a status into the table and returns the ID of the newly added
    /// status.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a status with the same name.
    pub fn insert(&self, description: &str) -> Result<u32> {
        let entry = Status {
            id: u32::MAX,
            description: description.to_string(),
        };
        self.indexed_map.insert(entry)
    }

    /// Update the status name from `old` to `new`, given `id`.
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

    /// Returns the status with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, id: u32) -> Result<Status> {
        let res = self
            .indexed_map
            .get_by_id(id)
            .and_then(|r| r.ok_or(anyhow::anyhow!("status {id} unavailable")))?;
        let c = super::deserialize(res.as_ref())?;
        Ok(c)
    }

    /// Try adding default entries into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    // The following will be used when PostgreSQL status table is deleted
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
        self.deactivate(added)?; // 0 is deactivated as id for `status`.

        for (id, name) in DEFAULT_ENTRIES {
            let added = self.insert(name)?;
            if added != id {
                self.remove(added)?; // so that `added` could be re-used as id.
                return Ok(());
            }
        }
        Ok(())
    }

    /// Returns `n` `status`(ies)
    /// `is_first`: Forward or Reverse order.
    /// `from`: If `from` exists in database then, `bound` is excluded from the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    fn get_n(&self, from: Option<Status>, n: usize, is_first: bool) -> Result<Vec<Status>> {
        use rocksdb::{Direction, IteratorMode};
        let key = from.as_ref().map(|v| v.indexed_key());
        let mode = match (&key, is_first) {
            (Some(from), true) => IteratorMode::From(from, Direction::Forward),
            (Some(from), false) => IteratorMode::From(from, Direction::Reverse),
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

    /// Returns `limit` # of `status`(ies) according to conditions provided.
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

    use crate::{types::Status, Store};

    use super::DEFAULT_ENTRIES;

    fn set_up_db() -> (Arc<Store>, Vec<Status>) {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.status_map();

        let testers = &["c", "a", "b", "d"];
        let mut entries: Vec<_> = DEFAULT_ENTRIES
            .iter()
            .map(|(i, d)| Status {
                id: *i,
                description: d.to_string(),
            })
            .chain(testers.iter().map(|d| Status {
                id: u32::MAX,
                description: d.to_string(),
            }))
            .collect();

        for e in entries.iter_mut().skip(DEFAULT_ENTRIES.len()) {
            let added = table.insert(&e.description).unwrap();
            e.id = added as u32;
        }

        entries.sort_unstable_by_key(|v| v.description.clone());

        (store, entries)
    }

    #[test]
    fn add() {
        let (store, entries) = set_up_db();
        let table = store.status_map();

        assert_eq!(table.count().unwrap(), entries.len());
    }

    #[test]
    fn get() {
        let (store, entries) = set_up_db();
        let table = store.status_map();

        for entry in entries {
            assert_eq!(table.get(entry.id).unwrap(), entry);
        }
    }

    #[test]
    fn update_for_new_existing_key() {
        let (store, entries) = set_up_db();
        let mut table = store.status_map();

        assert!(table
            .update(
                entries
                    .iter()
                    .find_map(|v| {
                        if v.description == "a" {
                            Some(v.id)
                        } else {
                            None
                        }
                    })
                    .unwrap(),
                "a",
                "b"
            )
            .is_err());

        assert_eq!(table.count().unwrap(), entries.len());
    }

    #[test]
    fn get_range_before() {
        let (store, entries) = set_up_db();

        let table = store.status_map();

        let res = table
            .get_range(Some(entries[0].clone()), None, false, 2)
            .unwrap();
        assert_eq!(res.len(), 0);

        let res = table
            .get_range(Some(entries[3].clone()), None, false, 2)
            .unwrap();
        assert_eq!(
            res,
            entries[1..3].into_iter().rev().cloned().collect::<Vec<_>>()
        );
    }

    #[test]
    fn get_range_after() {
        let (store, entries) = set_up_db();

        let table = store.status_map();
        let res = table
            .get_range(None, Some(entries[3].clone()), true, 2)
            .unwrap();
        assert_eq!(res, entries[4..6]);

        let res = table
            .get_range(None, Some(entries[2].clone()), true, 2)
            .unwrap();
        assert_eq!(res, entries[3..5]);
    }

    #[test]
    fn get_range_first() {
        let (store, entries) = set_up_db();

        let table = store.status_map();

        let res = table.get_range(None, None, true, 2).unwrap();
        assert_eq!(res, entries[..2],);
    }

    #[test]
    fn get_range_last() {
        let (store, entries) = set_up_db();

        let table = store.status_map();

        let res1 = table.get_range(None, None, false, 2).unwrap();
        let res2 = table
            .get_range(Some(entries[5].clone()), Some(entries[0].clone()), false, 2)
            .unwrap();

        assert_eq!(res1, res2);
        assert_eq!(
            res1,
            entries[entries.len() - 2..]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}
