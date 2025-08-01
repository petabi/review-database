//! The `block_network` table.

use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    HostNetworkGroup, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BlockNetwork {
    pub id: u32,
    pub name: String,
    pub networks: HostNetworkGroup,
    pub description: String,
}

impl FromKeyValue for BlockNetwork {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for BlockNetwork {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for BlockNetwork {
    fn key(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

pub struct Update {
    pub name: Option<String>,
    pub networks: Option<HostNetworkGroup>,
    pub description: Option<String>,
}

impl IndexedMapUpdate for Update {
    type Entry = BlockNetwork;

    fn key(&self) -> Option<Cow<[u8]>> {
        self.name.as_deref().map(str::as_bytes).map(Cow::Borrowed)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(name);
        }
        if let Some(networks) = self.networks.as_ref() {
            networks.clone_into(&mut value.networks);
        }
        if let Some(description) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(description);
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref() {
            if v != value.name {
                return false;
            }
        }
        if let Some(v) = self.networks.as_ref() {
            if *v != value.networks {
                return false;
            }
        }
        if let Some(v) = self.description.as_deref() {
            if v != value.description {
                return false;
            }
        }
        true
    }
}

/// Functions for the `block_network` indexed map.
impl<'d> IndexedTable<'d, BlockNetwork> {
    /// Opens the `block_network` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::BLOCK_NETWORKS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `BlockNetwork` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::{BlockNetwork, HostNetworkGroup, Iterable, Store};

    #[test]
    fn put_and_get() {
        let store = setup_store();
        let table = store.block_network_map();

        let a = create_block_network("a", "TestDescription");
        let inserted_id = table.put(a.clone()).unwrap();

        let retrieved_block_network = table.get_by_id(inserted_id).unwrap().unwrap();
        assert_eq!(retrieved_block_network, a);

        assert!(table.put(a).is_err());

        let b = create_block_network("b", "TestDescription");
        let b_id = table.put(b).unwrap();
        assert!(b_id != inserted_id);

        assert_eq!(2, table.iter(Direction::Forward, None).count());
    }

    #[test]
    fn update() {
        let store = setup_store();
        let mut table = store.block_network_map();

        let block_network = create_block_network("AllowNetwork1", "Description1");
        let inserted_id = table.put(block_network.clone()).unwrap();
        let old = super::Update {
            name: Some(block_network.name.clone()),
            networks: Some(block_network.networks.clone()),
            description: Some(block_network.description.clone()),
        };

        let updated_block_network =
            create_block_network("UpdatedAllowNetwork", "UpdatedDescription");
        let update = super::Update {
            name: Some(updated_block_network.name.clone()),
            networks: Some(updated_block_network.networks.clone()),
            description: Some(updated_block_network.description.clone()),
        };

        table.update(inserted_id, &old, &update).unwrap();

        let retrieved_block_network = table.get_by_id(inserted_id).unwrap().unwrap();
        assert_eq!(retrieved_block_network, updated_block_network);
    }

    #[test]
    fn update_key() {
        let store = setup_store();
        let mut table = store.block_network_map();

        let mut a = create_block_network("a", "a");
        a.id = table.put(a.clone()).unwrap();
        let a_update = super::Update {
            name: Some(a.name.clone()),
            networks: Some(a.networks.clone()),
            description: Some(a.description.clone()),
        };
        let mut b = create_block_network("b", "b");
        b.id = table.put(b.clone()).unwrap();
        let b_update = super::Update {
            name: Some(b.name.clone()),
            networks: Some(b.networks.clone()),
            description: Some(b.description.clone()),
        };

        let c_update = super::Update {
            name: Some("c".to_string()),
            networks: Some(HostNetworkGroup::default()),
            description: Some("c".to_string()),
        };

        assert!(table.update(a.id, &a_update, &c_update).is_ok());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);

        // Old entry must match existing entry
        assert!(table.update(0, &a_update, &c_update).is_err());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);

        // No duplicated keys
        assert!(table.update(0, &c_update, &b_update).is_err());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);
    }

    // Helper functions

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_block_network(name: &str, description: &str) -> BlockNetwork {
        BlockNetwork {
            id: 0,
            name: name.to_string(),
            networks: HostNetworkGroup::default(),
            description: description.to_string(),
        }
    }
}
