//! The accounts table.

use std::net::IpAddr;

use anyhow::{bail, Context};
use bincode::Options;
use rocksdb::{Direction, IteratorMode, OptimisticTransactionDB};

use crate::{
    types::{Account, SaltedPassword},
    IterableMap, Map, MapIterator, Role, Table, EXCLUSIVE,
};

/// Functions for the accounts table.
impl<'d> Table<'d, Account> {
    /// Opens the accounts table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCOUNTS).map(Table::new)
    }

    /// Returns `true` if the table contains an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str) -> Result<bool, anyhow::Error> {
        self.map.get(username.as_bytes()).map(|v| v.is_some())
    }

    /// Deletes an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn delete(&self, username: &str) -> Result<(), anyhow::Error> {
        self.map.delete(username.as_bytes())
    }

    /// Returns an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn get(&self, username: &str) -> Result<Option<Account>, anyhow::Error> {
        let Some(value) = self.map.get(username.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(
            bincode::DefaultOptions::new().deserialize::<Account>(value.as_ref())?,
        ))
    }

    /// Stores an account into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the account fails or the database operation fails.
    pub fn put(&self, account: &Account) -> Result<(), anyhow::Error> {
        let value = bincode::DefaultOptions::new().serialize(account)?;
        self.map.put(account.username.as_bytes(), &value)
    }

    /// Adds an account into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization of the account fails, the account with the same
    /// username exists, or the database operation fails.
    pub fn insert(&self, account: &Account) -> Result<(), anyhow::Error> {
        let value = bincode::DefaultOptions::new().serialize(account)?;
        self.map.insert(account.username.as_bytes(), &value)
    }

    /// Replaces an old key-value pair with a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the database, the old key does
    /// not exist, or the database operation fails.
    pub(crate) fn update_raw(
        &self,
        old: (&[u8], &[u8]),
        new: (&[u8], &[u8]),
    ) -> Result<(), anyhow::Error> {
        self.map.update(old, new)
    }

    /// Updates an entry in account map.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    ///
    /// * The account stored in the database in invalid.
    /// * Random number generation for a password salt fails.
    /// * The old values do not match the values in the database.
    /// * The underlying database operation fails.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn update(
        &self,
        username: &[u8],
        new_password: &Option<String>,
        role: Option<(Role, Role)>,
        name: &Option<(String, String)>,
        department: &Option<(String, String)>,
        allow_access_from: &Option<(Option<Vec<IpAddr>>, Option<Vec<IpAddr>>)>,
        max_parallel_sessions: &Option<(Option<u32>, Option<u32>)>,
    ) -> Result<(), anyhow::Error> {
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

impl<'i> IterableMap<'i, MapIterator<'i>> for Table<'i, Account> {
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
