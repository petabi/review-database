//! The `account_policy` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table};

pub const ACCOUNT_POLICY_KEY: &[u8] = b"account policy key";

#[derive(Serialize, Deserialize)]
pub struct AccountPolicy {
    pub(crate) expiry_period_in_secs: u32,
    pub(crate) lockout_threshold: u32,
    pub(crate) lockout_duration_in_secs: u32,
    pub(crate) suspension_threshold: u32,
}

/// Functions for the `account_policy` map.
impl<'d> Table<'d, AccountPolicy> {
    /// Opens the  `account_policy` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCOUNT_POLICY).map(Table::new)
    }

    /// Initializes the account policy.
    ///
    /// # Errors
    ///
    /// Returns an error if it has already been initialized or
    /// if database operation fails.
    pub fn init_account_policy(
        &self,
        expiry_period_in_secs: u32,
        lockout_threshold: u32,
        lockout_duration_in_secs: u32,
        suspension_threshold: u32,
    ) -> Result<()> {
        let init = AccountPolicy {
            expiry_period_in_secs,
            lockout_threshold,
            lockout_duration_in_secs,
            suspension_threshold,
        };
        self.map
            .insert(ACCOUNT_POLICY_KEY, &super::serialize(&init)?)
    }

    /// Updates or initializes the account policy.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn update_account_policy(
        &self,
        expiry_period_in_secs: Option<u32>,
        lockout_threshold: Option<u32>,
        lockout_duration_in_secs: Option<u32>,
        suspension_threshold: Option<u32>,
    ) -> Result<()> {
        if let Some(old_data) = self.map.get(ACCOUNT_POLICY_KEY)? {
            let old_policy: AccountPolicy = super::deserialize(old_data.as_ref())?;
            let update = AccountPolicy {
                expiry_period_in_secs: expiry_period_in_secs
                    .unwrap_or(old_policy.expiry_period_in_secs),
                lockout_threshold: lockout_threshold.unwrap_or(old_policy.lockout_threshold),
                lockout_duration_in_secs: lockout_duration_in_secs
                    .unwrap_or(old_policy.lockout_duration_in_secs),
                suspension_threshold: suspension_threshold
                    .unwrap_or(old_policy.suspension_threshold),
            };
            let update_data = super::serialize(&update)?;
            self.map.update(
                (ACCOUNT_POLICY_KEY, old_data.as_ref()),
                (ACCOUNT_POLICY_KEY, &update_data),
            )
        } else {
            // Initialize with default values if not set
            let expiry_period = expiry_period_in_secs.unwrap_or(0);
            let lockout_threshold = lockout_threshold.unwrap_or(5);
            let lockout_duration = lockout_duration_in_secs.unwrap_or(1800);
            let suspension_threshold = suspension_threshold.unwrap_or(10);

            self.init_account_policy(
                expiry_period,
                lockout_threshold,
                lockout_duration,
                suspension_threshold,
            )
        }
    }

    /// Returns the current account policy,
    /// or `None` if it hasn't been initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn current_account_policy(&self) -> Result<Option<AccountPolicy>> {
        self.map
            .get(ACCOUNT_POLICY_KEY)?
            .map(|p| super::deserialize(p.as_ref()))
            .transpose()
    }

    /// Returns the current expiry period,
    /// or `None` if it hasn't been initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn current_expiry_period(&self) -> Result<Option<u32>> {
        self.current_account_policy()
            .map(|policy| policy.map(|p| p.expiry_period_in_secs))
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

        // Test initializing with all parameters
        assert!(table.init_account_policy(10, 5, 1800, 10).is_ok());
        let policy = table.current_account_policy().unwrap().unwrap();
        assert_eq!(policy.expiry_period_in_secs, 10);
        assert_eq!(policy.lockout_threshold, 5);
        assert_eq!(policy.lockout_duration_in_secs, 1800);
        assert_eq!(policy.suspension_threshold, 10);

        // Test updating individual fields
        assert!(
            table
                .update_account_policy(Some(20), None, None, None)
                .is_ok()
        );
        let policy = table.current_account_policy().unwrap().unwrap();
        assert_eq!(policy.expiry_period_in_secs, 20);
        assert_eq!(policy.lockout_threshold, 5); // unchanged
        assert_eq!(policy.lockout_duration_in_secs, 1800); // unchanged
        assert_eq!(policy.suspension_threshold, 10); // unchanged

        // Test updating multiple fields
        assert!(
            table
                .update_account_policy(Some(30), Some(8), Some(3600), Some(15))
                .is_ok()
        );
        let policy = table.current_account_policy().unwrap().unwrap();
        assert_eq!(policy.expiry_period_in_secs, 30);
        assert_eq!(policy.lockout_threshold, 8);
        assert_eq!(policy.lockout_duration_in_secs, 3600);
        assert_eq!(policy.suspension_threshold, 15);

        // Test backward compatibility
        assert_eq!(table.current_expiry_period().unwrap(), Some(30));
    }

    #[test]
    fn test_migration_compatibility() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_policy_map();

        // Test that update_account_policy can be called on empty table with defaults
        assert!(
            table
                .update_account_policy(Some(60), None, None, None)
                .is_ok()
        );
        let policy = table.current_account_policy().unwrap().unwrap();
        assert_eq!(policy.expiry_period_in_secs, 60);
        assert_eq!(policy.lockout_threshold, 5); // Default
        assert_eq!(policy.lockout_duration_in_secs, 1800); // Default
        assert_eq!(policy.suspension_threshold, 10); // Default
    }
}
