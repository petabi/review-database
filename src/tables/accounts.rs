//! The accounts table.

use std::net::IpAddr;

use anyhow::{Context, bail};
use bincode::Options;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{
    EXCLUSIVE, Map, Role, Table,
    account::{PasswordHashAlgorithm, SaltedPassword},
    types::{Account, FromKeyValue},
};

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub(crate) struct LegacyAccount {
    pub username: String,
    pub password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    pub language: Option<String>,
    pub theme: Option<String>,
    pub creation_time: DateTime<Utc>,
    pub last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u8>,
    pub password_hash_algorithm: PasswordHashAlgorithm,
    pub password_last_modified_at: DateTime<Utc>,
    pub customer_ids: Option<Vec<u32>>,
}

impl From<LegacyAccount> for Account {
    fn from(legacy: LegacyAccount) -> Self {
        Self {
            username: legacy.username,
            password: legacy.password,
            role: legacy.role,
            name: legacy.name,
            department: legacy.department,
            language: legacy.language,
            theme: legacy.theme,
            creation_time: legacy.creation_time,
            last_signin_time: legacy.last_signin_time,
            allow_access_from: legacy.allow_access_from,
            max_parallel_sessions: legacy.max_parallel_sessions,
            password_hash_algorithm: legacy.password_hash_algorithm,
            password_last_modified_at: legacy.password_last_modified_at,
            customer_ids: legacy.customer_ids,
            failed_login_attempts: 0,
            locked_out_until: None,
            is_suspended: false,
        }
    }
}

impl FromKeyValue for Account {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        let options = bincode::DefaultOptions::new();

        if let Ok(account) = options.deserialize::<Account>(value) {
            Ok(account)
        } else if let Ok(legacy_account) = options.deserialize::<LegacyAccount>(value) {
            Ok(legacy_account.into())
        } else {
            Err(anyhow::anyhow!("Failed to deserialize account data"))
        }
    }
}

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

        let options = bincode::DefaultOptions::new();
        let account = if let Ok(account) = options.deserialize::<Account>(value.as_ref()) {
            account
        } else if let Ok(legacy_account) = options.deserialize::<LegacyAccount>(value.as_ref()) {
            legacy_account.into()
        } else {
            return Err(anyhow::anyhow!("Failed to deserialize account data"));
        };

        Ok(Some(account))
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
        language: &Option<(Option<String>, Option<String>)>,
        theme: &Option<(Option<String>, Option<String>)>,
        allow_access_from: &Option<(Option<Vec<IpAddr>>, Option<Vec<IpAddr>>)>,
        max_parallel_sessions: &Option<(Option<u8>, Option<u8>)>,
        customer_ids: &Option<(Option<Vec<u32>>, Option<Vec<u32>>)>,
    ) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username, EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let mut account =
                    if let Ok(account) = options.deserialize::<Account>(old_value.as_ref()) {
                        account
                    } else if let Ok(legacy_account) =
                        options.deserialize::<LegacyAccount>(old_value.as_ref())
                    {
                        legacy_account.into()
                    } else {
                        return Err(anyhow::anyhow!("Failed to deserialize account data"));
                    };

                if let Some(password) = &new_password {
                    account.update_password(password)?;
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
                    account.name.clone_from(new);
                }
                if let Some((old, new)) = &department {
                    if account.department != *old {
                        bail!("old value mismatch");
                    }
                    account.department.clone_from(new);
                }
                if let Some((old, new)) = language {
                    if account.language != *old {
                        bail!("old value mismatch");
                    }
                    account.language.clone_from(new);
                }
                if let Some((old, new)) = theme {
                    if account.theme != *old {
                        bail!("old value mismatch");
                    }
                    account.theme.clone_from(new);
                }
                if let Some((old, new)) = &allow_access_from {
                    if account.allow_access_from != *old {
                        bail!("old value mismatch");
                    }
                    account.allow_access_from.clone_from(new);
                }
                if let Some((old, new)) = max_parallel_sessions {
                    if account.max_parallel_sessions != *old {
                        bail!("old value mismatch");
                    }
                    account.max_parallel_sessions = *new;
                }
                if let Some((old, new)) = customer_ids {
                    if account.customer_ids != *old {
                        bail!("old value mismatch");
                    }
                    account.customer_ids.clone_from(new);
                }

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username, value)
                    .context("failed to write new entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Increments the failed login attempts for an account with the given username.
    /// If the account reaches the lockout threshold, it will be locked out.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn increment_failed_login(&self, username: &str) -> Result<(), anyhow::Error> {
        const LOCKOUT_THRESHOLD: u8 = 5;
        const LOCKOUT_DURATION_MINUTES: i64 = 30;

        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let mut account =
                    if let Ok(account) = options.deserialize::<Account>(old_value.as_ref()) {
                        account
                    } else if let Ok(legacy_account) =
                        options.deserialize::<LegacyAccount>(old_value.as_ref())
                    {
                        legacy_account.into()
                    } else {
                        return Err(anyhow::anyhow!("Failed to deserialize account data"));
                    };

                account.failed_login_attempts = account.failed_login_attempts.saturating_add(1);

                if account.failed_login_attempts >= LOCKOUT_THRESHOLD {
                    account.locked_out_until =
                        Some(Utc::now() + chrono::Duration::minutes(LOCKOUT_DURATION_MINUTES));
                }

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to increment failed login");
                    }
                }
            }
        }
        Ok(())
    }

    /// Clears the failed login attempts for an account with the given username.
    /// Also unlocks the account if it was locked out.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn clear_failed_logins(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let mut account =
                    if let Ok(account) = options.deserialize::<Account>(old_value.as_ref()) {
                        account
                    } else if let Ok(legacy_account) =
                        options.deserialize::<LegacyAccount>(old_value.as_ref())
                    {
                        legacy_account.into()
                    } else {
                        return Err(anyhow::anyhow!("Failed to deserialize account data"));
                    };

                account.failed_login_attempts = 0;
                account.locked_out_until = None;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to clear failed logins");
                    }
                }
            }
        }
        Ok(())
    }

    /// Checks if an account is currently locked out.
    /// Automatically unlocks accounts whose lockout period has expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn is_account_locked(&self, username: &str) -> Result<bool, anyhow::Error> {
        let Some(account) = self.get(username)? else {
            bail!("no such entry");
        };

        if let Some(locked_until) = account.locked_out_until {
            if Utc::now() >= locked_until {
                self.clear_failed_logins(username)?;
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    /// Suspends an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn suspend_account(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let mut account =
                    if let Ok(account) = options.deserialize::<Account>(old_value.as_ref()) {
                        account
                    } else if let Ok(legacy_account) =
                        options.deserialize::<LegacyAccount>(old_value.as_ref())
                    {
                        legacy_account.into()
                    } else {
                        return Err(anyhow::anyhow!("Failed to deserialize account data"));
                    };

                account.is_suspended = true;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to suspend account");
                    }
                }
            }
        }
        Ok(())
    }

    /// Unsuspends an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn unsuspend_account(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let mut account =
                    if let Ok(account) = options.deserialize::<Account>(old_value.as_ref()) {
                        account
                    } else if let Ok(legacy_account) =
                        options.deserialize::<LegacyAccount>(old_value.as_ref())
                    {
                        legacy_account.into()
                    } else {
                        return Err(anyhow::anyhow!("Failed to deserialize account data"));
                    };

                account.is_suspended = false;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to unsuspend account");
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns all accounts with their security status information.
    /// This method is useful for administrative dashboards showing user security states.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_accounts_with_security_status(&self) -> Result<Vec<Account>, anyhow::Error> {
        use crate::Iterable;

        let mut accounts = Vec::new();
        let iter = self.iter(crate::Direction::Forward, None);

        for account in iter {
            accounts.push(account?);
        }

        Ok(accounts)
    }

    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{Direction, Role, Store, types::Account};

    #[test]
    fn put_delete() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        assert!(!table.contains("user1").unwrap());
        let acc1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();
        assert!(table.contains("user1").unwrap());

        let acc2 = Account::new(
            "user2",
            "password",
            Role::SystemAdministrator,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();
        assert!(table.contains("user2").unwrap());

        table.delete("user1").unwrap();
        assert!(!table.contains("user1").unwrap());
    }

    #[test]
    fn iter() {
        use crate::Iterable;

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let mut iter = table.iter(Direction::Forward, None);
        assert!(iter.next().is_none());

        let acc1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();

        let mut iter = table.iter(Direction::Forward, None);
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user1");
        assert!(iter.next().is_none());

        let acc2 = Account::new(
            "user2",
            "password",
            Role::SystemAdministrator,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();

        let mut iter = table.iter(Direction::Forward, Some(b"user2"));
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user2");

        let mut iter = table.iter(Direction::Reverse, None);
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user2");

        let mut iter = table.iter(Direction::Reverse, Some(b"user1"));
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user1");
    }

    #[test]
    fn put_duplicate_key() {
        use crate::Iterable;

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        // Insert first account
        let acc1 = Account::new(
            "user1",
            "password1",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();
        assert!(table.contains("user1").unwrap());

        // Get the first account to verify it was stored
        let retrieved_acc1 = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved_acc1.username, "user1");
        assert_eq!(retrieved_acc1.name, "User 1");
        assert_eq!(retrieved_acc1.department, "Department 1");

        // Insert second account with same username but different data
        let acc2 = Account::new(
            "user1",     // Same username
            "password2", // Different password
            Role::SystemAdministrator,
            "User 1 Updated".to_string(), // Different name
            "Department 2".to_string(),   // Different department
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();

        // Verify the account was overwritten with new data
        let retrieved_acc2 = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved_acc2.username, "user1");
        assert_eq!(retrieved_acc2.name, "User 1 Updated");
        assert_eq!(retrieved_acc2.department, "Department 2");

        // Verify password was updated by checking the passwords match the respective accounts
        assert!(!retrieved_acc2.verify_password("password1")); // Old password should not work
        assert!(retrieved_acc2.verify_password("password2")); // New password should work

        // Verify there's only one entry in the table (the duplicate key overwrote the original)
        let mut iter = table.iter(Direction::Forward, None);
        let first_entry = iter.next().unwrap().unwrap();
        assert_eq!(first_entry.username, "user1");
        assert_eq!(first_entry.name, "User 1 Updated"); // Should have the updated data
        assert!(iter.next().is_none()); // Should be no more entries
    }

    #[test]
    fn test_failed_login_attempts() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account).unwrap();

        assert!(!table.is_account_locked("user1").unwrap());

        table.increment_failed_login("user1").unwrap();
        let retrieved = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved.failed_login_attempts, 1);
        assert!(retrieved.locked_out_until.is_none());

        for _ in 0..4 {
            table.increment_failed_login("user1").unwrap();
        }

        let locked_account = table.get("user1").unwrap().unwrap();
        assert_eq!(locked_account.failed_login_attempts, 5);
        assert!(locked_account.locked_out_until.is_some());
        assert!(table.is_account_locked("user1").unwrap());

        table.clear_failed_logins("user1").unwrap();
        let cleared_account = table.get("user1").unwrap().unwrap();
        assert_eq!(cleared_account.failed_login_attempts, 0);
        assert!(cleared_account.locked_out_until.is_none());
        assert!(!table.is_account_locked("user1").unwrap());
    }

    #[test]
    fn test_account_suspension() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account).unwrap();

        let initial_account = table.get("user1").unwrap().unwrap();
        assert!(!initial_account.is_suspended);

        table.suspend_account("user1").unwrap();
        let suspended_account = table.get("user1").unwrap().unwrap();
        assert!(suspended_account.is_suspended);

        table.unsuspend_account("user1").unwrap();
        let unsuspended_account = table.get("user1").unwrap().unwrap();
        assert!(!unsuspended_account.is_suspended);
    }

    #[test]
    fn test_get_accounts_with_security_status() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let account1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account1).unwrap();

        let account2 = Account::new(
            "user2",
            "password",
            Role::SecurityMonitor,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account2).unwrap();

        table.suspend_account("user1").unwrap();
        table.increment_failed_login("user2").unwrap();

        let security_accounts = table.get_accounts_with_security_status().unwrap();
        assert_eq!(security_accounts.len(), 2);

        let user1 = security_accounts
            .iter()
            .find(|a| a.username == "user1")
            .unwrap();
        assert!(user1.is_suspended);
        assert_eq!(user1.failed_login_attempts, 0);

        let user2 = security_accounts
            .iter()
            .find(|a| a.username == "user2")
            .unwrap();
        assert!(!user2.is_suspended);
        assert_eq!(user2.failed_login_attempts, 1);
    }

    #[test]
    fn test_version_aware_deserialization() {
        use bincode::Options;

        use super::LegacyAccount;
        use crate::account::{PasswordHashAlgorithm, SaltedPassword};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let legacy_account = LegacyAccount {
            username: "legacy_user".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "password",
                &PasswordHashAlgorithm::Argon2id,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            name: "Legacy User".to_string(),
            department: "Legacy Dept".to_string(),
            language: None,
            theme: None,
            creation_time: chrono::Utc::now(),
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2id,
            password_last_modified_at: chrono::Utc::now(),
            customer_ids: None,
        };

        let serialized_legacy = bincode::DefaultOptions::new()
            .serialize(&legacy_account)
            .unwrap();

        table
            .raw()
            .put("legacy_user".as_bytes(), &serialized_legacy)
            .unwrap();

        let retrieved_account = table.get("legacy_user").unwrap().unwrap();
        assert_eq!(retrieved_account.username, "legacy_user");
        assert_eq!(retrieved_account.name, "Legacy User");
        assert_eq!(retrieved_account.failed_login_attempts, 0);
        assert!(retrieved_account.locked_out_until.is_none());
        assert!(!retrieved_account.is_suspended);
    }

    #[test]
    fn test_lockout_expiration() {
        use std::{thread, time::Duration};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.account_map();

        let mut account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        account.failed_login_attempts = 5;
        account.locked_out_until = Some(chrono::Utc::now() + chrono::Duration::milliseconds(100));
        table.put(&account).unwrap();

        assert!(table.is_account_locked("user1").unwrap());

        thread::sleep(Duration::from_millis(200));

        assert!(!table.is_account_locked("user1").unwrap());

        let unlocked_account = table.get("user1").unwrap().unwrap();
        assert_eq!(unlocked_account.failed_login_attempts, 0);
        assert!(unlocked_account.locked_out_until.is_none());
    }
}
