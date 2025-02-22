use anyhow::{Context, Result, anyhow};
use bincode::Options;

use super::KeyIndex;
use crate::EXCLUSIVE;

pub struct IndexedSet<'a> {
    db: &'a rocksdb::OptimisticTransactionDB,
    cf: &'a rocksdb::ColumnFamily,
    key: &'static [u8],
}

impl<'a> IndexedSet<'a> {
    pub(crate) fn new(
        db: &'a rocksdb::OptimisticTransactionDB,
        name: &str,
        key: &'static [u8],
    ) -> Result<Self> {
        db.cf_handle(name)
            .map(|cf| Self { db, cf, key })
            .ok_or_else(|| anyhow!("database error: cannot find column family \"{}\"", name))
    }

    /// Returns the index of the set.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or cannot be read.
    pub fn index(&self) -> Result<KeyIndex> {
        let Some(value) = self
            .db
            .get_cf(self.cf, self.key)
            .context("database error")?
        else {
            return Ok(KeyIndex::default());
        };
        KeyIndex::from_bytes(value).context("invalid index in database")
    }

    /// Deactivates an entry with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or any database operation fails.
    pub fn deactivate(&self, id: u32) -> Result<Vec<u8>> {
        let mut key;
        loop {
            let txn = self.db.transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            key = index.deactivate(id).context("cannot deactivate key")?;
            txn.put_cf(
                self.cf,
                self.key,
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Makes deactivated indices available.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or any database operation fails.
    pub fn clear_inactive(&self) -> Result<()> {
        loop {
            let txn = self.db.transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            index.clear_inactive()?;
            txn.put_cf(
                self.cf,
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Inserts an entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or any database operation fails.
    pub fn insert<T: AsRef<[u8]>>(&self, entry: T) -> Result<u32> {
        let mut i;
        loop {
            let txn = self.db.transaction();
            let mut index = self.index_in_transaction(&txn)?;
            i = index.insert(entry.as_ref()).context("cannot insert key")?;
            txn.put_cf(
                self.cf,
                self.key,
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store new entry");
                    }
                }
            }
        }
        Ok(i)
    }

    /// Removes an entry for the given ID, returning the removed entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or any database operation fails.
    pub fn remove(&self, id: u32) -> Result<Vec<u8>> {
        let mut key;
        loop {
            let txn = self.db.transaction();
            let mut index = self.index_in_transaction(&txn)?;
            key = index.remove(id).context("cannot remove key")?;
            txn.put_cf(
                self.cf,
                self.key,
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Updates an old entry to a new one for the given ID.
    ///
    /// It returns `true` if the entry was updated, and `false` if the entry was
    /// different or not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or any database operation fails.
    pub fn update(&self, id: u32, old: &[u8], new: &[u8]) -> Result<bool> {
        loop {
            let txn = self.db.transaction();
            let mut index = self.index_in_transaction(&txn)?;
            if let Some(v) = index.get(id).context("invalid ID")? {
                if v != old {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
            index
                .update(id, new.as_ref())
                .context("cannot update index")?;
            txn.put_cf(
                self.cf,
                self.key,
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(true)
    }

    fn index_in_transaction(
        &self,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<KeyIndex> {
        let Some(value) = txn
            .get_for_update_cf(self.cf, self.key, EXCLUSIVE)
            .context("database error")?
        else {
            return Ok(KeyIndex::default());
        };
        KeyIndex::from_bytes(value).context("invalid index in database")
    }
}

#[cfg(test)]
mod tests {
    use crate::test;

    #[test]
    fn deactivate() {
        let db = test::Store::new();
        let set = db.indexed_set();
        let id_a = set.insert(b"a").unwrap();
        assert_eq!(id_a, 0);
        let id_b = set.insert(b"b").unwrap();
        assert_eq!(id_b, 1);

        let key = set.deactivate(id_b).unwrap();
        assert_eq!(key, b"b");

        let index = set.index().unwrap();
        let mut iter = index.iter();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn remove() {
        let db = test::Store::new();
        let set = db.indexed_set();
        let _id_a = set.insert(b"a").unwrap();
        let id_b = set.insert(b"b").unwrap();

        let key = set.remove(id_b).unwrap();
        assert_eq!(key, b"b");

        let index = set.index().unwrap();
        let mut iter = index.iter();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }
}
