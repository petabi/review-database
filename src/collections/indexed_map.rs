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

    fn indexed_key(&self, key: Vec<u8>, _id: u32) -> Vec<u8> {
        key
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

    /// Gets a value corresponding to the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or cannot be read.
    pub fn get_by_id(&self, id: u32) -> Result<Option<impl AsRef<[u8]>>> {
        let index = self.index()?;
        let Some(key) = index.get(id).context("invalid ID")? else {
            return Ok(None)
        };
        self.db.get_cf(self.cf, key).context("cannot read entry")
    }

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
