//! The `network` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{types::FromKeyValue, Indexable, Indexed, IndexedMap, IndexedMapUpdate, IndexedTable};

type PortNumber = u16;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct Settings {
    pub customer_id: u32,
    pub description: String,
    pub hostname: String,

    pub piglet: bool,
    pub piglet_giganto_ip: Option<IpAddr>,
    pub piglet_giganto_port: Option<PortNumber>,
    pub save_packets: bool,
    pub http: bool,
    pub office: bool,
    pub exe: bool,
    pub pdf: bool,
    pub txt: bool,
    pub vbs: bool,
    pub smtp_eml: bool,
    pub ftp: bool,

    pub giganto: bool,
    pub giganto_ingestion_ip: Option<IpAddr>,
    pub giganto_ingestion_port: Option<PortNumber>,
    pub giganto_publish_ip: Option<IpAddr>,
    pub giganto_publish_port: Option<PortNumber>,
    pub giganto_graphql_ip: Option<IpAddr>,
    pub giganto_graphql_port: Option<PortNumber>,
    pub retention_period: Option<u16>,

    pub reconverge: bool,

    pub hog: bool,
    pub hog_giganto_ip: Option<IpAddr>,
    pub hog_giganto_port: Option<PortNumber>,
    pub protocols: Option<Vec<String>>,

    pub sensors: Option<Vec<String>>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Node {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub settings: Option<Settings>,
    pub settings_draft: Option<Settings>,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for Node {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl Indexable for Node {
    fn key(&self) -> Cow<[u8]> {
        Cow::from(self.name.as_bytes())
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

/// Functions for the `node` indexed map.
impl<'d> IndexedTable<'d, Node> {
    /// Opens the `node` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .ok()
    }

    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        &self.indexed_map
    }

    /// Updates the `Node` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

pub struct Update {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub settings: Option<Settings>,
    pub settings_draft: Option<Settings>,
}

impl From<Node> for Update {
    fn from(input: Node) -> Update {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            settings: input.settings,
            settings_draft: input.settings_draft,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = Node;

    fn key(&self) -> Option<Cow<[u8]>> {
        self.name.as_deref().map(|n| Cow::Borrowed(n.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(n) = self.name.as_deref() {
            n.clone_into(&mut value.name);
        }
        value.name_draft.clone_from(&self.name_draft);
        value.settings.clone_from(&self.settings);
        value.settings_draft.clone_from(&self.settings_draft);
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(n) = self.name.as_deref() {
            if n != value.name {
                return false;
            }
        }
        if self.name_draft != value.name_draft {
            return false;
        }
        if self.settings != value.settings {
            return false;
        }
        self.settings_draft == value.settings_draft
    }
}
