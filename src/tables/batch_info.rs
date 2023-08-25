//! The `batch_info` table.

use anyhow::Result;
use rocksdb::{IteratorMode, OptimisticTransactionDB};

use crate::{types::BatchInfo, Map, Table};

impl<'d> Table<'d, BatchInfo> {
    /// Opens the batch info table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::BATCH_INFO).map(Table::new)
    }

    /// Adds a `batch_info` entry into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the batch info fails, the batch info entry with the
    /// same model and id exists, or the database operation fails.
    pub fn insert(&self, batch_info: &BatchInfo) -> Result<()> {
        let key = super::serialize(&batch_info.key())?;
        let value = super::serialize(&batch_info.value())?;
        self.map.insert(&key, &value)
    }

    /// Stores a a `batch_info` entry into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the `batch_info` fails or the database operation fails.
    pub fn put(&self, batch_info: &BatchInfo) -> Result<()> {
        let key = super::serialize(&batch_info.key())?;
        let value = super::serialize(&batch_info.value())?;
        self.map.put(&key, &value)
    }

    /// Deletes all `batch_info`s with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if any of deletion operation fails.
    pub fn delete_all_for(&self, model: i32) -> Result<usize> {
        let mut deleted = 0;
        let prefix = super::serialize(&model)?;
        for (k, _v) in self.map.inner_prefix_iterator(IteratorMode::End, &prefix) {
            match self.map.delete(&k) {
                Ok(_) => deleted += 1,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Deleted: {deleted}\nDeletion ended due to: {e}"
                    ))
                }
            }
            deleted += 1;
        }
        Ok(deleted)
    }
}
