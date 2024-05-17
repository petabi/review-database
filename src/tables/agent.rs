//! The agent table.

use std::{borrow::Cow, fmt::Display, mem::size_of};

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use crate::{types::FromKeyValue, Indexable, IndexedMap, IndexedTable};

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    EnumString,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum Kind {
    Reconverge = 1,
    Piglet = 2,
    Hog = 3,
    // Crusher,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    inner: String,
}

impl TryFrom<String> for Config {
    type Error = anyhow::Error;

    fn try_from(inner: String) -> Result<Self> {
        toml::from_str(&inner)?;
        Ok(Self { inner })
    }
}

impl AsRef<str> for Config {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

pub struct Agent {
    node: u32,
    key: String,
    id: u32,
    kind: Kind,
    config: Option<Config>,
    draft: Option<Config>,
}

impl Agent {
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node: u32,
        key: String,
        kind: Kind,
        config: Option<String>,
        draft: Option<String>,
    ) -> Result<Self> {
        let id = u32::MAX;
        let config = config.map(TryInto::try_into).transpose()?;
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node,
            key,
            id,
            kind,
            config,
            draft,
        })
    }
}

impl FromKeyValue for Agent {
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
            id: value.id,
            kind: value.kind,
            config: value.config,
            draft: value.draft,
        })
    }
}

impl Indexable for Agent {
    fn key(&self) -> Cow<[u8]> {
        let mut buf = self.node.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        Cow::Owned(buf)
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        let value = Value {
            id: self.id,
            kind: self.kind,
            config: self.config.clone(),
            draft: self.draft.clone(),
        };
        super::serialize(&value).expect("value should be serializable.")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    id: u32,
    kind: Kind,
    config: Option<Config>,
    draft: Option<Config>,
}

/// Functions for the agents table.
impl<'d> IndexedTable<'d, Agent> {
    /// Opens the agents table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::AGENTS)
            .map(IndexedTable::new)
            .ok()
    }
}
