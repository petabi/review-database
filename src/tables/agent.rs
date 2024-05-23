//! The agent table.

use std::{borrow::Cow, fmt::Display, mem::size_of};

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use crate::{types::FromKeyValue, Map, Table, UniqueKey};

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
        let config = config.map(TryInto::try_into).transpose()?;
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node,
            key,
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
            kind: value.kind,
            config: value.config,
            draft: value.draft,
        })
    }
}

impl UniqueKey for Agent {
    fn unique_key(&self) -> Cow<[u8]> {
        let mut buf = self.node.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        Cow::Owned(buf)
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    kind: Kind,
    config: Option<Config>,
    draft: Option<Config>,
}

/// Functions for the agents table.
impl<'d> Table<'d, Agent> {
    /// Opens the agents table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::AGENTS).map(Table::new)
    }
}
