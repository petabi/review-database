//! The remote table.

use std::mem::size_of;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::{RemoteConfig, RemoteKind, RemoteStatus};
use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Remote {
    pub node: u32,
    pub key: String,
    pub kind: RemoteKind,
    pub status: RemoteStatus,
    pub draft: Option<RemoteConfig>,
}

impl Remote {
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node: u32,
        key: String,
        kind: RemoteKind,
        status: RemoteStatus,
        draft: Option<String>,
    ) -> Result<Self> {
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node,
            key,
            kind,
            status,
            draft,
        })
    }
}

impl FromKeyValue for Remote {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;

        let (node, key) = key.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(node);
        let node = u32::from_be_bytes(buf);
        let key = std::str::from_utf8(key)?.to_string();

        Ok(Self {
            node,
            key,
            kind: value.kind,
            status: value.status,
            draft: value.draft,
        })
    }
}

impl UniqueKey for Remote {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        buf
    }
}

impl ValueTrait for Remote {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        let value = Value {
            kind: self.kind,
            status: self.status,
            draft: self.draft.clone(),
        };
        super::serialize(&value).expect("serializable")
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    kind: RemoteKind,
    status: RemoteStatus,
    draft: Option<RemoteConfig>,
}

/// Functions for the remotes table.
impl<'d> Table<'d, Remote> {
    /// Opens the remotes table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::REMOTES).map(Table::new)
    }

    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }

    /// Returns an remote with the given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the remote does not exist or the database operation fails.
    pub fn get(&self, node: u32, id: &str) -> Result<Option<Remote>> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Remote::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the remote with given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node: u32, id: &str) -> Result<()> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        self.map.delete(&key)
    }

    /// Updates the `Remote` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &Remote, new: &Remote) -> Result<()> {
        let (ok, ov) = (old.unique_key(), old.value());
        let (nk, nv) = (new.unique_key(), new.value());
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    const VALID_TOML: &str = r#"test = "true""#;
    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_remote(node: u32, key: &str, kind: RemoteKind, draft: Option<&str>) -> Remote {
        Remote::new(
            node,
            key.to_string(),
            kind,
            RemoteStatus::Enabled,
            draft.map(ToString::to_string),
        )
        .unwrap()
    }

    #[test]
    fn remote_creation() {
        let remote = create_remote(1, "test_key", RemoteKind::Datalake, Some(VALID_TOML));
        assert_eq!(remote.node, 1);
        assert_eq!(remote.key, "test_key");
        assert_eq!(remote.kind, RemoteKind::Datalake);
        assert_eq!(remote.draft.as_ref().unwrap().as_ref(), VALID_TOML);

        let invalid = "invalid";
        assert!(
            Remote::new(
                1,
                "test_key".to_string(),
                RemoteKind::Datalake,
                RemoteStatus::Enabled,
                Some(invalid.to_string()),
            )
            .is_err()
        );
    }

    #[test]
    fn config_try_from() {
        let config = RemoteConfig::try_from(VALID_TOML.to_string()).unwrap();
        assert_eq!(config.as_ref(), VALID_TOML);
    }

    #[test]
    fn serialization() {
        let remote = create_remote(1, "test_key", RemoteKind::TiContainer, Some(VALID_TOML));
        let serialized = remote.value();
        let deserialized = Remote::from_key_value(&remote.unique_key(), &serialized).unwrap();
        assert_eq!(remote, deserialized);
    }

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.remotes_map();

        let remote = create_remote(1, "test_key", RemoteKind::Datalake, None);

        // Insert and retrieve remote
        assert!(table.insert(&remote).is_ok());
        let retrieved_remote = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(remote, retrieved_remote);

        let new_toml = r#"another_test = "abc""#;
        // Update remote
        let updated_remote = create_remote(1, "test_key", RemoteKind::TiContainer, Some(new_toml));
        table.update(&remote, &updated_remote).unwrap();
        let retrieved_updated_remote = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(updated_remote, retrieved_updated_remote);

        // Delete remote
        table.delete(1, "test_key").unwrap();
        let result = table.get(1, "test_key").unwrap();
        assert!(result.is_none());
    }
}
