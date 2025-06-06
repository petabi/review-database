//! The unlinked server table.

use std::mem::size_of;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::{UnlinkedServerConfig, UnlinkedServerKind, UnlinkedServerStatus};
use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UnlinkedServer {
    pub node: u32,
    pub key: String,
    pub kind: UnlinkedServerKind,
    pub status: UnlinkedServerStatus,
    pub draft: Option<UnlinkedServerConfig>,
}

impl UnlinkedServer {
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node: u32,
        key: String,
        kind: UnlinkedServerKind,
        status: UnlinkedServerStatus,
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

impl FromKeyValue for UnlinkedServer {
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

impl UniqueKey for UnlinkedServer {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        buf
    }
}

impl ValueTrait for UnlinkedServer {
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
    kind: UnlinkedServerKind,
    status: UnlinkedServerStatus,
    draft: Option<UnlinkedServerConfig>,
}

/// Functions for the unlinked servers table.
impl<'d> Table<'d, UnlinkedServer> {
    /// Opens the unlinked servers table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::UNLINKED_SERVERS).map(Table::new)
    }

    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }

    /// Returns an unlinked server with the given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the unlinked server does not exist or the database operation fails.
    pub fn get(&self, node: u32, id: &str) -> Result<Option<UnlinkedServer>> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(UnlinkedServer::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the unlinked server with given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node: u32, id: &str) -> Result<()> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        self.map.delete(&key)
    }

    /// Updates the `UnlinkedServer` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &UnlinkedServer, new: &UnlinkedServer) -> Result<()> {
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

    fn create_unlinked_server(
        node: u32,
        key: &str,
        kind: UnlinkedServerKind,
        draft: Option<&str>,
    ) -> UnlinkedServer {
        UnlinkedServer::new(
            node,
            key.to_string(),
            kind,
            UnlinkedServerStatus::Enabled,
            draft.map(ToString::to_string),
        )
        .unwrap()
    }

    #[test]
    fn unlinked_server_creation() {
        let unlinked_server = create_unlinked_server(
            1,
            "test_key",
            UnlinkedServerKind::Datalake,
            Some(VALID_TOML),
        );
        assert_eq!(unlinked_server.node, 1);
        assert_eq!(unlinked_server.key, "test_key");
        assert_eq!(unlinked_server.kind, UnlinkedServerKind::Datalake);
        assert_eq!(unlinked_server.draft.as_ref().unwrap().as_ref(), VALID_TOML);

        let invalid = "invalid";
        assert!(
            UnlinkedServer::new(
                1,
                "test_key".to_string(),
                UnlinkedServerKind::Datalake,
                UnlinkedServerStatus::Enabled,
                Some(invalid.to_string()),
            )
            .is_err()
        );
    }

    #[test]
    fn config_try_from() {
        let config = UnlinkedServerConfig::try_from(VALID_TOML.to_string()).unwrap();
        assert_eq!(config.as_ref(), VALID_TOML);
    }

    #[test]
    fn serialization() {
        let unlinked_server = create_unlinked_server(
            1,
            "test_key",
            UnlinkedServerKind::TiContainer,
            Some(VALID_TOML),
        );
        let serialized = unlinked_server.value();
        let deserialized =
            UnlinkedServer::from_key_value(&unlinked_server.unique_key(), &serialized).unwrap();
        assert_eq!(unlinked_server, deserialized);
    }

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.unlinked_servers_map();

        let unlinked_server =
            create_unlinked_server(1, "test_key", UnlinkedServerKind::Datalake, None);

        // Insert and retrieve an unlinked server
        assert!(table.insert(&unlinked_server).is_ok());
        let retrieved_unlinked_server = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(unlinked_server, retrieved_unlinked_server);

        let new_toml = r#"another_test = "abc""#;
        // Update unlinked_server
        let updated_unlinked_server = create_unlinked_server(
            1,
            "test_key",
            UnlinkedServerKind::TiContainer,
            Some(new_toml),
        );
        table
            .update(&unlinked_server, &updated_unlinked_server)
            .unwrap();
        let retrieved_updated_unlinked_server = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(updated_unlinked_server, retrieved_updated_unlinked_server);

        // Delete an unlinked server
        table.delete(1, "test_key").unwrap();
        let result = table.get(1, "test_key").unwrap();
        assert!(result.is_none());
    }
}
