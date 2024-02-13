//! The `qualifier` table.
use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{
    types::{FromKeyValue, Qualifier},
    Indexable, Indexed, IndexedMap, IndexedMapUpdate, IndexedTable,
};

// The following will be used when PostgreSQL qualifier table is deleted
const DEFAULT_ENTRIES: [(u32, &str); 4] = [
    (1, "benign"),
    (2, "unknown"),
    (3, "suspicious"),
    (4, "mixed"),
];

impl Indexable for Qualifier {
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

impl IndexedMapUpdate for Qualifier {
    type Entry = Qualifier;

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

impl<'d> IndexedTable<'d, Qualifier> {
    /// Opens the qualifier table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let table = IndexedMap::new(db, super::QUALIFIERS)
            .map(IndexedTable::new)
            .ok()?;
        table.setup().ok()?;
        Some(table)
    }

    /// Inserts a qualifier into the table and returns the ID of the newly added
    /// qualifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a qualifier with the same name.
    pub fn insert(&self, description: &str) -> Result<u32> {
        let entry = Qualifier {
            id: u32::MAX,
            description: description.to_string(),
        };
        self.indexed_map.insert(entry)
    }

    /// Update the qualifier name from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> Result<()> {
        let new = Qualifier {
            id: u32::MAX,
            description: new.to_string(),
        };
        let old = Qualifier {
            id: u32::MAX,
            description: old.to_string(),
        };
        self.indexed_map.update(id, &old, &new)
    }

    /// Returns the qualifier with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, id: u32) -> Result<Qualifier> {
        let (key, value) = self
            .indexed_map
            .get_by_id(id)
            .and_then(|r| r.ok_or(anyhow::anyhow!("qualifier {id} unavailable")))?;
        let c = Qualifier::from_key_value(&key, &value)?;
        Ok(c)
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
        self.deactivate(added)?; // 0 is deactivated as id for `qualifier`.

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

    use crate::{types::Qualifier, Store};

    use super::DEFAULT_ENTRIES;

    fn set_up_db() -> (Arc<Store>, Vec<Qualifier>) {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.qualifier_map();

        let testers = &["c", "a", "b", "d"];
        let mut entries: Vec<_> = DEFAULT_ENTRIES
            .iter()
            .map(|(i, d)| Qualifier {
                id: *i,
                description: d.to_string(),
            })
            .chain(testers.iter().map(|d| Qualifier {
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
        let table = store.qualifier_map();

        assert_eq!(table.count().unwrap(), entries.len());
    }

    #[test]
    fn get() {
        let (store, entries) = set_up_db();
        let table = store.qualifier_map();

        for entry in entries {
            assert_eq!(table.get(entry.id).unwrap(), entry);
        }
    }

    #[test]
    fn update_for_new_existing_key() {
        let (store, entries) = set_up_db();
        let mut table = store.qualifier_map();

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
}
