//! The `trusted_domain` table.

use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use super::Value;
use crate::{types::FromKeyValue, Map, Table, UniqueKey};

#[derive(Clone)]
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

impl UniqueKey for TrustedDomain {
    fn unique_key(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }
}

impl Value for TrustedDomain {
    fn value(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.remarks.as_bytes())
    }
}

/// Functions for the `trusted_domain` map.
impl<'d> Table<'d, TrustedDomain> {
    /// Opens the  `trusted_domain` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRUSTED_DNS_SERVERS).map(Table::new)
    }

    /// Removes a `trusted_domain` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::{Iterable, Store, TrustedDomain};

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.trusted_domain_map();

        let a = create_entry("a");
        assert!(table.put(&a).is_ok());

        let b = create_entry("b");
        assert!(table.insert(&b).is_ok());

        assert_eq!(table.iter(Direction::Forward, None).count(), 2);
        assert!(table.remove(b.name.as_str()).is_ok());
        assert!(table.remove(a.name.as_str()).is_ok());
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
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
