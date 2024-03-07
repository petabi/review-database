//! The `access_token` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{types::FromKeyValue, Map, Table};

#[derive(Debug, PartialEq)]
pub struct AccessToken {
    pub username: String,
    pub token: String,
}

impl AccessToken {
    fn create_key_value(username: &str, token: &str) -> (Vec<u8>, Vec<u8>) {
        let mut key = username.as_bytes().to_owned();
        key.push(0);
        key.extend(token.as_bytes());
        (key, vec![])
    }
}

impl FromKeyValue for AccessToken {
    fn from_key_value(key: &[u8], _value: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let sep = key
            .iter()
            .position(|c| *c == 0)
            .ok_or(anyhow!("corruptted access token"))?;
        let username = String::from_utf8_lossy(&key[..sep]).into_owned();
        let token = String::from_utf8_lossy(&key[sep + 1..]).into_owned();
        Ok(AccessToken { username, token })
    }
}

/// Functions for the `access_token` map.
impl<'d> Table<'d, AccessToken> {
    /// Opens the  `access_token` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCESS_TOKENS).map(Table::new)
    }

    /// Insert `(username, token)` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, username: &str, token: &str) -> Result<()> {
        let (key, value) = AccessToken::create_key_value(username, token);
        self.map.insert(&key, &value)
    }

    /// Remove `(username, token)` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn revoke(&self, username: &str, token: &str) -> Result<()> {
        let (key, _value) = AccessToken::create_key_value(username, token);

        self.map.delete(&key)
    }

    /// Find whether `username` `token` exists in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str, token: &str) -> Result<bool> {
        let (key, _value) = AccessToken::create_key_value(username, token);
        self.map.get(&key).map(|v| v.is_some())
    }
}
