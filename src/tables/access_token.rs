//! The `access_token` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use super::KeyValue;
use crate::{types::FromKeyValue, Map, Table};

#[derive(Debug, PartialEq)]
pub struct AccessToken {
    pub username: String,
    pub token: String,
}

impl AccessToken {
    #[cfg(test)]
    pub(crate) fn create_key_value(username: &str, token: &str) -> (Vec<u8>, Vec<u8>) {
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

impl KeyValue<(&str, &str), ()> for AccessToken {
    fn db_key(&self) -> (&str, &str) {
        (&self.username, &self.token)
    }

    fn db_value(&self) {}

    fn from_key_value(key: (&str, &str), _value: ()) -> Self {
        AccessToken {
            username: key.0.to_owned(),
            token: key.1.to_owned(),
        }
    }
}

/// Functions for the `access_token` map.
impl<'db, 'n, 'd> Table<'db, 'n, 'd, AccessToken, (&str, &str), ()> {
    /// Opens the  `access_token` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCESS_TOKENS).map(Table::new)
    }

    /// Inserts `(username, token)` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, username: &str, token: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        let mut tbl = txn.open_table::<(&str, &str), ()>(self.def)?;
        tbl.insert((username, token), ())?;
        drop(tbl);
        txn.commit()?;
        Ok(())
    }

    /// Removes `(username, token)` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn revoke(&self, username: &str, token: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        let mut tbl = txn.open_table::<(&str, &str), ()>(self.def)?;
        tbl.remove((username, token))?;
        drop(tbl);
        txn.commit()?;
        Ok(())
    }

    /// Finds whether `username` `token` exists in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str, token: &str) -> Result<bool> {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table::<(&str, &str), ()>(self.def)?;
        Ok(tbl.get((username, token))?.is_some())
    }

    /// Finds all tokens for `username` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn tokens(
        &self,
        username: &str,
    ) -> Result<super::Range<'_, AccessToken, (&'static str, &'static str), ()>> {
        let upper_bound = username.to_string() + "\0";
        self.range((username, "")..(&upper_bound, ""))
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::Store;

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.access_token_map();
        let names = &["abc", "abcd", "def"];

        for (count, name) in names.iter().enumerate() {
            for i in 0..count + 1 {
                assert!(table.insert(name, &i.to_string()).is_ok());
            }
        }

        for (count, name) in names.iter().enumerate() {
            assert_eq!(count + 1, table.tokens(name).unwrap().count());
            for i in 0..count + 1 {
                assert!(table.contains(name, &i.to_string()).unwrap());
            }
            assert!(table.revoke(name, &0.to_string()).is_ok());
            assert!(!table.contains(name, &0.to_string()).unwrap());
        }

        drop(table)
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }
}
