//! The `batch_info` table.

use anyhow::Result;
use rocksdb::{IteratorMode, OptimisticTransactionDB};

use crate::{batch_info::BatchInfo, Map, Table};

use super::{Key, Value};

impl<'d> Table<'d, crate::batch_info::BatchInfo> {
    /// Opens the batch info table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::BATCH_INFO).map(Table::new)
    }

    /// Stores `batch_info` into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the `batch_info` fails or the database operation fails.
    pub fn put(&self, input: &BatchInfo) -> Result<()> {
        let key = super::serialize(&input.key())?;
        let value = super::serialize(&input.value())?;
        self.map.put(&key, &value)
    }

    /// Adds `batch_info` into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the `batch_info` fails, the `batch_info` with the same
    /// key exists, or the database operation fails.
    pub fn insert(&self, input: &BatchInfo) -> Result<()> {
        let key = super::serialize(&input.key())?;
        let value = super::serialize(&input.value())?;
        self.map.insert(&key, &value)
    }

    /// Returns all `batch_info` with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn get_all_for(&self, model: i32) -> Result<Vec<BatchInfo>> {
        let prefix = super::serialize(&model)?;
        let mut batch_info = vec![];
        for (k, v) in self.map.inner_prefix_iterator(IteratorMode::Start, &prefix) {
            let (_, id): (i32, i64) = super::deserialize(&k)?;
            let (earliest, latest, sources) = super::deserialize(&v)?;
            let inner = crate::types::ModelBatchInfo {
                id,
                earliest,
                latest,
                sources,
            };
            batch_info.push(BatchInfo::new(model, inner));
        }
        Ok(batch_info)
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
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{batch_info::BatchInfo, types::ModelBatchInfo, Store};

    #[test]
    fn put_delete() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.batch_info_map();

        assert_eq!(table.get_all_for(1).unwrap().len(), 0);
        assert_eq!(table.get_all_for(2).unwrap().len(), 0);

        let entry1 = BatchInfo::new(
            1,
            ModelBatchInfo {
                id: 321,
                earliest: 1,
                latest: 2,
                sources: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
        );
        let entry2 = BatchInfo::new(
            1,
            ModelBatchInfo {
                id: 121,
                earliest: 1,
                latest: 2,
                sources: vec!["a".to_string(), "b".to_string()],
            },
        );
        let entry3 = BatchInfo::new(
            2,
            ModelBatchInfo {
                id: 123,
                earliest: 1,
                latest: 2,
                sources: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
        );

        let entries = vec![&entry1, &entry2, &entry3];

        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }

        let res = table.get_all_for(1).unwrap();
        assert_eq!(res.len(), 2);
        for (r, e) in res.into_iter().zip(vec![&entry2, &entry1].into_iter()) {
            assert_eq!(&r, e);
        }

        assert_eq!(2, table.delete_all_for(1).unwrap());
        assert_eq!(1, table.delete_all_for(2).unwrap());

        assert_eq!(table.get_all_for(1).unwrap().len(), 0);
        assert_eq!(table.get_all_for(2).unwrap().len(), 0);
    }
}
