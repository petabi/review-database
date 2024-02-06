use super::Indexed;
use anyhow::{anyhow, Context, Result};
use std::mem::size_of;

/// A multimap where each key has an associated numerical ID.
///
/// The IDs are stored in the first entry, i.e., under an empty key, as a
/// serialized `Vec`.
pub struct IndexedMultimap<'a> {
    db: &'a rocksdb::OptimisticTransactionDB,
    cf: &'a rocksdb::ColumnFamily,
}

impl<'a> Indexed for IndexedMultimap<'a> {
    fn db(&self) -> &rocksdb::OptimisticTransactionDB {
        self.db
    }

    fn cf(&self) -> &rocksdb::ColumnFamily {
        self.cf
    }

    fn indexed_key(&self, mut key: Vec<u8>, id: u32) -> Vec<u8> {
        let len = key.len() + size_of::<u32>();
        key.resize(len, 0);
        key[len - size_of::<u32>()..].copy_from_slice(&id.to_be_bytes());
        key
    }
}

impl<'a> IndexedMultimap<'a> {
    /// Creates a new `IndexedMultimap`.
    ///
    /// # Errors
    ///
    /// Returns an error if the column family cannot be found.
    pub fn new(db: &'a rocksdb::OptimisticTransactionDB, name: &str) -> Result<Self> {
        db.cf_handle(name)
            .map(|cf| Self { db, cf })
            .ok_or_else(|| anyhow!("database error: cannot find column family \"{}\"", name))
    }

    /// Gets a value corresponding to the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or cannot be read.
    pub fn get_kv_by_id(&self, id: u32) -> Result<Option<(impl AsRef<[u8]>, impl AsRef<[u8]>)>> {
        let index = self.index()?;
        let mut key = if let Some(key) = index.get(id).context("invalid ID")? {
            key.to_vec()
        } else {
            return Ok(None);
        };
        key.extend(id.to_be_bytes().iter());
        let value = self
            .db
            .get_cf(self.cf, &key)
            .context("cannot read entry")?
            .ok_or_else(|| anyhow!("invalid database index"))?;
        Ok(Some((key, value)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        collections::{tests::TestStore, Indexable, Indexed},
        IterableMap,
    };
    use std::{borrow::Cow, mem::size_of};

    struct TestEntry {
        indexed_key: Vec<u8>,
        value: Vec<u8>,
    }

    impl Indexable for TestEntry {
        fn key(&self) -> Cow<[u8]> {
            Cow::Borrowed(&self.indexed_key[..self.indexed_key.len() - size_of::<u32>()])
        }

        fn indexed_key(&self) -> Cow<[u8]> {
            Cow::Borrowed(&self.indexed_key)
        }

        fn value(&self) -> Vec<u8> {
            self.value.clone()
        }

        fn set_index(&mut self, index: u32) {
            let offset = self.indexed_key.len() - size_of::<u32>();
            self.indexed_key[offset..].copy_from_slice(&index.to_be_bytes());
        }
    }

    #[test]
    fn insert_duplicate() {
        let db = TestStore::new();
        let map = db.indexed_multimap();

        assert_eq!(map.count().unwrap(), 0);
        let id = map
            .insert(TestEntry {
                indexed_key: vec![b'a', 0, 0, 0, 0],
                value: vec![0],
            })
            .unwrap();
        assert_eq!(map.count().unwrap(), 1);
        assert_eq!(id, 0);

        let id = map
            .insert(TestEntry {
                indexed_key: vec![b'a', 0, 0, 0, 0],
                value: vec![0],
            })
            .unwrap();
        assert_eq!(map.count().unwrap(), 2);
        assert_eq!(id, 1);
    }

    #[test]
    fn remove() {
        let db = TestStore::new();
        let map = db.indexed_multimap();
        map.insert(TestEntry {
            indexed_key: vec![b'a', 0, 0, 0, 0],
            value: vec![0],
        })
        .unwrap();
        map.insert(TestEntry {
            indexed_key: vec![b'b', 0, 0, 0, 0],
            value: vec![0],
        })
        .unwrap();
        map.insert(TestEntry {
            indexed_key: vec![b'c', 0, 0, 0, 0],
            value: vec![0],
        })
        .unwrap();

        let key = map.remove(1).unwrap();
        assert_eq!(key, &[b'b']);
        assert!(map.get_kv_by_id(1).unwrap().is_none());
        let mut iter = map.iter_forward().unwrap();
        let (key, _) = iter.next().expect("containing at least two entries");
        assert_eq!(key.as_ref(), &[b'a', 0, 0, 0, 0]);
        let (key, _) = iter.next().expect("containing at least two entries");
        assert_eq!(key.as_ref(), &[b'c', 0, 0, 0, 2]);
        assert!(iter.next().is_none());
    }
}
