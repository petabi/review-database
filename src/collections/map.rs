use super::IterableMap;
use crate::EXCLUSIVE;
use anyhow::{anyhow, bail, Context, Result};
use rocksdb::{Direction, IteratorMode};

pub struct Map<'a> {
    pub(crate) db: &'a rocksdb::OptimisticTransactionDB,
    pub(crate) cf: &'a rocksdb::ColumnFamily,
}

impl<'a> Map<'a> {
    pub(crate) fn open(db: &'a rocksdb::OptimisticTransactionDB, name: &str) -> Option<Self> {
        db.cf_handle(name).map(|cf| Self { db, cf })
    }

    /// Deletes a key-value pair with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist or the database operation fails.
    pub fn delete(&self, key: &[u8]) -> Result<(), anyhow::Error> {
        self.db
            .delete_cf(self.cf, key)
            .map_err(|e| anyhow!("database error: {}", e))
    }

    /// Gets a value corresponding to the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist or the database operation fails.
    pub fn get(&self, key: &[u8]) -> Result<Option<impl AsRef<[u8]>>> {
        self.db
            .get_cf(self.cf, key)
            .map_err(|e| anyhow!("database error: {}", e))
    }

    /// Puts a key-value pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db
            .put_cf(self.cf, key, value)
            .map_err(|e| anyhow!("database error: {}", e))
    }

    /// Inserts a new key-value pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key already exists or the database operation fails.
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let txn = self.db.transaction();
        if txn
            .get_for_update_cf(self.cf, key, EXCLUSIVE)
            .context("database read error")?
            .is_some()
        {
            bail!("key already exists");
        }
        txn.put_cf(self.cf, key, value)
            .context("failed to write new entry")?;

        match txn.commit() {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.as_ref().starts_with("Resource busy:") {
                    Err(anyhow!("already exists"))
                } else {
                    Err(e).context("failed to insert entry")
                }
            }
        }
    }

    /// Replaces the entire key-value pairs with new ones.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn replace_all(&self, new: &[(&[u8], &[u8])]) -> Result<()> {
        loop {
            let txn = self.db.transaction();

            for (old_key, _) in self.inner_iterator(IteratorMode::Start) {
                txn.delete_cf(self.cf, old_key)
                    .context("failed to delete entries")?;
            }

            for (key, value) in new {
                txn.put_cf(self.cf, key, value)
                    .context("failed to write new entry")?;
            }

            match txn.commit() {
                Ok(_) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to replace entries");
                    }
                }
            }
        }

        Ok(())
    }

    /// Updates an old key-value pair to a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the database, the old key does
    /// not exist, or the database operation fails.
    pub fn update(&self, old: (&[u8], &[u8]), new: (&[u8], &[u8])) -> Result<()> {
        loop {
            let txn = self.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.cf, old.0, EXCLUSIVE)
                .context("cannot read old entry")?
            {
                if old.1 != old_value.as_slice() {
                    bail!("old value mismatch");
                }
            } else {
                bail!("no such entry");
            };

            txn.put_cf(self.cf, new.0, new.1)
                .context("failed to write new entry")?;
            if old.0 != new.0 {
                txn.delete_cf(self.cf, old.0)
                    .context("failed to delete old entry")?;
            }

            match txn.commit() {
                Ok(_) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn into_prefix_map(self, prefix: &'a [u8]) -> PrefixMap {
        PrefixMap { prefix, map: self }
    }

    fn inner_iterator(&self, mode: IteratorMode) -> MapIterator {
        let iter = self.db.iterator_cf(self.cf, mode);

        MapIterator { inner: iter }
    }

    fn inner_prefix_iterator(&self, mode: IteratorMode, prefix: &[u8]) -> MapIterator {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let iter = self.db.iterator_cf_opt(self.cf, readopts, mode);

        MapIterator { inner: iter }
    }
}

impl<'i> IterableMap<'i, MapIterator<'i>> for Map<'i> {
    fn iter_from(&self, key: &[u8], direction: Direction) -> Result<MapIterator> {
        Ok(self.inner_iterator(IteratorMode::From(key, direction)))
    }

    fn iter_forward(&self) -> Result<MapIterator> {
        Ok(self.inner_iterator(IteratorMode::Start))
    }

    fn iter_backward(&self) -> Result<MapIterator> {
        Ok(self.inner_iterator(IteratorMode::End))
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct PrefixMap<'a, 'b> {
    prefix: &'a [u8],
    map: Map<'b>,
}

impl<'a, 'b, 'i> IterableMap<'i, MapIterator<'i>> for PrefixMap<'a, 'b> {
    fn iter_from(&self, key: &[u8], direction: Direction) -> Result<MapIterator> {
        Ok(self
            .map
            .inner_prefix_iterator(IteratorMode::From(key, direction), self.prefix))
    }

    fn iter_forward(&self) -> Result<MapIterator> {
        Ok(self
            .map
            .inner_prefix_iterator(IteratorMode::Start, self.prefix))
    }

    fn iter_backward(&self) -> Result<MapIterator> {
        Ok(self
            .map
            .inner_prefix_iterator(IteratorMode::End, self.prefix))
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct MapIterator<'i> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
}

impl<'i> MapIterator<'i> {
    pub(crate) fn new(
        inner: rocksdb::DBIteratorWithThreadMode<
            'i,
            rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
        >,
    ) -> Self {
        Self { inner }
    }
}

impl<'i> Iterator for MapIterator<'i> {
    type Item = (Box<[u8]>, Box<[u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().transpose().ok().flatten()
    }
}
