//! The `account_policy` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table};

pub(crate) const ACCOUNT_POLICY_KEY: &[u8] = b"account policy key";

#[derive(Serialize, Deserialize)]
pub struct AccountPolicy {
    pub(crate) expiry_period_in_secs: u32,
}

/// Functions for the `account_policy` map.
impl<'d> Table<'d, AccountPolicy> {
    /// Opens the  `account_policy` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCOUNT_POLICY).map(Table::new)
    }

    /// Initializes the expiry period.
    ///
    /// # Errors
    ///
    /// Returns an error if it has already been initialized or
    /// if database operation fails.
    pub fn init_expiry_period(&self, secs: u32) -> Result<()> {
        let init = AccountPolicy {
            expiry_period_in_secs: secs,
        };
        self.map
            .insert(ACCOUNT_POLICY_KEY, &super::serialize(&init)?)
    }

    /// Updates or initializes the expiry period.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn update_expiry_period(&self, secs: u32) -> Result<()> {
        if let Some(old) = self.map.get(ACCOUNT_POLICY_KEY)? {
            let update = super::serialize(&AccountPolicy {
                expiry_period_in_secs: secs,
            })?;
            self.map.update(
                (ACCOUNT_POLICY_KEY, old.as_ref()),
                (ACCOUNT_POLICY_KEY, &update),
            )
        } else {
            self.init_expiry_period(secs)
        }
    }

    /// Returns the current expiry period,
    /// or `None` if it hasn't been initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn current_expiry_period(&self) -> Result<Option<u32>> {
        self.map
            .get(ACCOUNT_POLICY_KEY)?
            .map(|p| super::deserialize(p.as_ref()).map(|p: AccountPolicy| p.expiry_period_in_secs))
            .transpose()
    }

    #[allow(unused)]
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
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_policy_map();

        assert!(table.update_expiry_period(10).is_ok());
        assert_eq!(table.current_expiry_period().unwrap(), Some(10));
        assert!(table.update_expiry_period(20).is_ok());
        assert_eq!(table.current_expiry_period().unwrap(), Some(20));
    }
}
