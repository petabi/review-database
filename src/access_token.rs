//! The `access_token` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::Map;

#[allow(clippy::module_name_repetitions)]
pub struct AccessTokenMap<'d> {
    inner: Map<'d>,
}

/// Functions for the `access_token` map.
impl<'d> AccessTokenMap<'d> {
    /// Opens the  `access_token` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::tables::ACCESS_TOKENS).map(|inner| AccessTokenMap { inner })
    }

    /// Insert `(username, token)` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, username: &str, token: &str) -> Result<()> {
        let key = to_key(username, token);
        self.inner.insert(&key, &[])
    }

    /// Remove `(username, token)` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn revoke(&self, username: &str, token: &str) -> Result<()> {
        let key = to_key(username, token);
        self.inner.delete(&key)
    }

    /// Find whether `username` `token` exists in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str, token: &str) -> Result<bool> {
        let key = to_key(username, token);
        self.inner.get(&key).map(|v| v.is_some())
    }

    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.inner
    }
}

fn to_key(username: &str, token: &str) -> Vec<u8> {
    let mut key = username.as_bytes().to_owned();
    key.push(0);
    key.extend(token.as_bytes());
    key
}
