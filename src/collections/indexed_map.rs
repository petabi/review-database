use super::Indexed;
use anyhow::{anyhow, bail, Context, Result};

/// A map where each key has an associated numerical ID.
///
/// The IDs are stored in the first entry, i.e., under an empty key, as a
/// serialized `Vec`.
pub struct IndexedMap<'a> {
    db: &'a rocksdb::OptimisticTransactionDB,
    cf: &'a rocksdb::ColumnFamily,
}

impl<'a> Indexed for IndexedMap<'a> {
    fn db(&self) -> &rocksdb::OptimisticTransactionDB {
        self.db
    }

    fn cf(&self) -> &rocksdb::ColumnFamily {
        self.cf
    }
}

impl<'a> IndexedMap<'a> {
    /// Creates a new `IndexedMap`.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be found.
    pub fn new(db: &'a rocksdb::OptimisticTransactionDB, name: &str) -> Result<Self> {
        db.cf_handle(name)
            .map(|cf| Self { db, cf })
            .ok_or_else(|| anyhow!("database error: cannot find column family \"{}\"", name))
    }

    /// Gets a key-value pair corresponding to the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or cannot be read.
    // pub fn get_by_id(&self, id: u32) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    //     let index = self.index()?;
    //     let Some(key) = index.get(id).context("invalid ID")? else {
    //         return Ok(None);
    //     };
    //     self.db
    //         .get_cf(self.cf, key)
    //         .context("cannot read entry")
    //         .map(|value| value.map(|value| (key.to_vec(), value)))
    // }

    /// Gets a value corresponding to the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty or cannot be read.
    pub fn get_by_key(&self, key: &[u8]) -> Result<Option<impl AsRef<[u8]>>> {
        if key.is_empty() {
            bail!("key shouldn't be empty");
        }
        self.db.get_cf(self.cf, key).context("cannot read entry")
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::{types::FromKeyValue, Indexable, Indexed, IndexedMapUpdate, Store};

    #[derive(serde::Deserialize, serde::Serialize, Clone)]
    struct TestEntry {
        id: u32,
        name: String,
    }

    impl FromKeyValue for TestEntry {
        fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
            use bincode::Options;
            Ok(bincode::DefaultOptions::new().deserialize(value)?)
        }
    }

    impl Indexable for TestEntry {
        fn key(&self) -> Cow<[u8]> {
            Cow::Borrowed(self.name.as_bytes())
        }
        fn index(&self) -> u32 {
            self.id
        }
        fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
            key
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

    impl IndexedMapUpdate for TestEntry {
        type Entry = TestEntry;

        fn key(&self) -> Option<Cow<[u8]>> {
            Some(Cow::Borrowed(self.name.as_bytes()))
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

    #[test]
    fn indexed_map_insert() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db = Store::new(&db_dir.path(), &backup_dir.path()).unwrap();
        let indexed = db.allow_network_map();

        assert!(indexed
            .insert(TestEntry {
                id: u32::MAX,
                name: "a".to_string()
            })
            .is_ok());
        assert!(indexed
            .insert(TestEntry {
                id: u32::MAX,
                name: "a".to_string()
            })
            .is_err());
        assert!(indexed
            .insert(TestEntry {
                id: u32::MAX,
                name: "b".to_string()
            })
            .is_ok());
    }

    #[test]
    fn indexed_map_update() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db = Store::new(&db_dir.path(), &backup_dir.path()).unwrap();
        let indexed = db.allow_network_map();

        let a = TestEntry {
            id: u32::MAX,
            name: "a".to_string(),
        };
        let b = TestEntry {
            id: u32::MAX,
            name: "b".to_string(),
        };
        let c = TestEntry {
            id: u32::MAX,
            name: "c".to_string(),
        };
        assert_eq!(indexed.insert(a.clone()).unwrap(), 0);
        assert_eq!(indexed.insert(b.clone()).unwrap(), 1);

        assert!(indexed.update(0, &a, &c).is_ok());
        assert_eq!(indexed.count().unwrap(), 2);

        // Old entry must match existing entry
        assert!(indexed.update(0, &a, &c).is_err());
        assert_eq!(indexed.count().unwrap(), 2);

        // No duplicated keys
        assert!(indexed.update(0, &c, &b).is_err());
        assert_eq!(indexed.count().unwrap(), 2);
    }
}
