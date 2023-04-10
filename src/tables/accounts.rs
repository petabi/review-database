use std::net::IpAddr;

use anyhow::{bail, Context};
use rocksdb::{Direction, IteratorMode, OptimisticTransactionDB};

use crate::{
    types::{Account, SaltedPassword},
    IterableMap, Map, MapIterator, Role, EXCLUSIVE,
};

impl<'d> super::Table<'d, Account> {
    /// Opens the accounts table in the database.
    ///
    /// # Panics
    ///
    /// Panics if the accounts table is not present in the database.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Self {
        let map = Map::new(db, super::ACCOUNTS).expect("accounts table is present");
        Self::new(map)
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), anyhow::Error> {
        self.map.delete(key)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<impl AsRef<[u8]>>, anyhow::Error> {
        self.map.get(key)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), anyhow::Error> {
        self.map.put(key, value)
    }

    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), anyhow::Error> {
        self.map.insert(key, value)
    }

    pub fn update(&self, old: (&[u8], &[u8]), new: (&[u8], &[u8])) -> Result<(), anyhow::Error> {
        self.map.update(old, new)
    }

    /// Updates an entry in account map.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn update_account(
        &self,
        username: &[u8],
        new_password: &Option<String>,
        role: Option<(Role, Role)>,
        name: &Option<(String, String)>,
        department: &Option<(String, String)>,
        allow_access_from: &Option<(Option<Vec<IpAddr>>, Option<Vec<IpAddr>>)>,
        max_parallel_sessions: &Option<(Option<u32>, Option<u32>)>,
    ) -> Result<(), anyhow::Error> {
        use bincode::Options;

        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username, EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let mut account =
                    bincode::DefaultOptions::new().deserialize::<Account>(old_value.as_ref())?;

                if let Some(password) = &new_password {
                    account.password = SaltedPassword::new(password)?;
                }
                if let Some((old, new)) = &role {
                    if account.role != *old {
                        bail!("old value mismatch");
                    }
                    account.role = *new;
                }
                if let Some((old, new)) = &name {
                    if account.name != *old {
                        bail!("old value mismatch");
                    }
                    account.name = new.clone();
                }
                if let Some((old, new)) = &department {
                    if account.department != *old {
                        bail!("old value mismatch");
                    }
                    account.department = new.clone();
                }
                if let Some((old, new)) = &allow_access_from {
                    if account.allow_access_from != *old {
                        bail!("old value mismatch");
                    }
                    account.allow_access_from = new.clone();
                }
                if let Some((old, new)) = max_parallel_sessions {
                    if account.max_parallel_sessions != *old {
                        bail!("old value mismatch");
                    }
                    account.max_parallel_sessions = *new;
                }

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username, value)
                    .context("failed to write new entry")?;
            } else {
                bail!("no such entry");
            };

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

    fn inner_iterator(&self, mode: IteratorMode) -> MapIterator {
        MapIterator::new(self.map.db.iterator_cf(self.map.cf, mode))
    }
}

impl<'i> IterableMap<'i, MapIterator<'i>> for super::Table<'i, Account> {
    fn iter_from(&self, key: &[u8], direction: Direction) -> Result<MapIterator, anyhow::Error> {
        Ok(self.inner_iterator(IteratorMode::From(key, direction)))
    }

    fn iter_forward(&self) -> Result<MapIterator, anyhow::Error> {
        Ok(self.inner_iterator(IteratorMode::Start))
    }

    fn iter_backward(&self) -> Result<MapIterator, anyhow::Error> {
        Ok(self.inner_iterator(IteratorMode::End))
    }
}
