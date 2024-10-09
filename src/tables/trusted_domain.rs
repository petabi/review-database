//! The `trusted_domain` table.

use anyhow::{bail, Result};
use redb::ReadableTable;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::KeyValue;
use crate::{types::FromKeyValue, Map, Table};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TrustedDomain {
    pub name: String,
    pub remarks: String,
}

impl FromKeyValue for TrustedDomain {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(TrustedDomain {
            name: std::str::from_utf8(key)?.to_owned(),
            remarks: std::str::from_utf8(value)?.to_owned(),
        })
    }
}

impl KeyValue<&str, &str> for TrustedDomain {
    fn db_key(&self) -> &str {
        &self.name
    }

    fn db_value(&self) -> &str {
        &self.remarks
    }

    fn from_key_value(key: &str, value: &str) -> Self {
        TrustedDomain {
            name: key.to_owned(),
            remarks: value.to_owned(),
        }
    }
}

/// Functions for the `trusted_domain` map.
impl<'db, 'n, 'd> Table<'db, 'n, 'd, TrustedDomain, &str, &str> {
    /// Opens the  `trusted_domain` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRUSTED_DNS_SERVERS).map(Table::new)
    }

    /// Updates the `TrustedDomain` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &TrustedDomain, new: &TrustedDomain) -> Result<()> {
        let txn = self.db.begin_write()?;
        let mut tbl = txn.open_table::<&str, &str>(self.def)?;
        let Some(val) = tbl.get(old.db_key())? else {
            bail!("no such entry");
        };
        if val.value() != old.db_value() {
            bail!("entry has been modified");
        }
        drop(val);
        tbl.remove(old.db_key())?;
        tbl.insert(new.db_key(), new.db_value())?;
        drop(tbl);
        txn.commit()?;
        Ok(())
    }

    /// Removes a `TrustedDomain` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        let mut tbl = txn.open_table::<&str, &str>(self.def)?;
        tbl.remove(name)?;
        drop(tbl);
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::{Store, TrustedDomain};

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.trusted_domain_map();

        let a = create_entry("a");
        assert!(table.upsert(&a).is_ok());

        let b = create_entry("b");
        assert!(table.upsert(&b).is_ok());

        assert_eq!(table.range::<&str>(..).unwrap().count(), 2);
        assert!(table.remove(b.name.as_str()).is_ok());
        assert!(table.remove(a.name.as_str()).is_ok());
        assert_eq!(table.range::<&str>(..).unwrap().count(), 0);
        drop(table);
    }

    #[test]
    fn update_test() {
        let store = setup_store();
        let table = store.trusted_domain_map();
        let origin = create_entry("origin");
        assert!(table.upsert(&origin).is_ok());

        let updated = TrustedDomain {
            name: "updated".to_string(),
            remarks: "updated remarks".to_string(),
        };
        assert!(table.update(&origin, &updated).is_ok());

        let mut iter = table.range::<&str>(..).unwrap();
        let entry = iter.next().unwrap().unwrap();
        assert_eq!(entry, updated);
        assert!(iter.next().is_none());
        let key = b"origin";
        let value = table.map.get(key).unwrap();
        assert!(value.is_none());
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_entry(name: &str) -> TrustedDomain {
        TrustedDomain {
            name: name.to_string(),
            remarks: "remarks".to_string(),
        }
    }
}
