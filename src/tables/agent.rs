//! The agent table.

use std::{borrow::Cow, fmt::Display, mem::size_of};

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use crate::{tables::Value as ValueTrait, types::FromKeyValue, Map, Table, UniqueKey};

#[derive(
    Serialize,
    Deserialize,
    Debug,
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Config {
    inner: String,
}

impl TryFrom<String> for Config {
    type Error = anyhow::Error;

    fn try_from(inner: String) -> Result<Self> {
        let _ = &inner.parse::<toml::Table>()?;
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

#[derive(Clone, Debug, PartialEq)]
pub struct Agent {
    pub node: u32,
    pub key: String,
    pub kind: Kind,
    pub config: Option<Config>,
    pub draft: Option<Config>,
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

impl ValueTrait for Agent {
    fn value(&self) -> Cow<[u8]> {
        let value = Value {
            kind: self.kind,
            config: self.config.clone(),
            draft: self.draft.clone(),
        };
        Cow::Owned(super::serialize(&value).expect("serializable"))
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

    /// Returns an agent with the given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent does not exist or the database operation fails.
    pub fn get(&self, node: u32, id: &str) -> Result<Option<Agent>> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Agent::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the agent with given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node: u32, id: &str) -> Result<()> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        self.map.delete(&key)
    }

    /// Updates the `Agent` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &Agent, new: &Agent) -> Result<()> {
        let (ok, ov) = (old.unique_key(), old.value());
        let (nk, nv) = (new.unique_key(), new.value());
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod test {
    use crate::Store;

    use super::*;
    use std::sync::Arc;
    const VALID_TOML:&str = r#"test = "true""#;
    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_agent(
        node: u32,
        key: &str,
        kind: Kind,
        config: Option<&str>,
        draft: Option<&str>,
    ) -> Agent {
        Agent::new(
            node,
            key.to_string(),
            kind,
            config.map(|s| s.to_string()),
            draft.map(|s| s.to_string()),
        )
        .unwrap()
    }

    #[test]
    fn agent_creation() {
        let agent = create_agent(1, "test_key", Kind::Reconverge, Some(VALID_TOML), Some(VALID_TOML));
        assert_eq!(agent.node, 1);
        assert_eq!(agent.key, "test_key");
        assert_eq!(agent.kind, Kind::Reconverge);
        assert_eq!(agent.config.as_ref().unwrap().as_ref(), VALID_TOML);
        assert_eq!(agent.draft.as_ref().unwrap().as_ref(), VALID_TOML);

        let invalid = "invalid";
        assert!(Agent::new(
            1,
            "test_key".to_string(),
            Kind::Reconverge,
            Some(invalid.to_string()),
            Some(invalid.to_string()),
        )
        .is_err());
    }

    #[test]
    fn config_try_from() {
        let config = Config::try_from(VALID_TOML.to_string()).unwrap();
        assert_eq!(config.as_ref(), VALID_TOML);
    }

    #[test]
    fn serialization() {
        let agent = create_agent(
            1,
            "test_key",
            Kind::Reconverge,
            Some(VALID_TOML),
            Some(VALID_TOML),
        );
        let serialized = agent.value();
        let deserialized = Agent::from_key_value(&agent.unique_key(), &serialized).unwrap();
        assert_eq!(agent, deserialized);
    }

    #[test]
    fn operations() {
        let store = setup_store();
        let table = store.agents_map();

        let agent = create_agent(
            1,
            "test_key",
            Kind::Reconverge,
            Some(VALID_TOML),
            None,
        );

        // Insert and retrieve agent
        assert!(table.insert(&agent).is_ok());
        let retrieved_agent = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(agent, retrieved_agent);

        let new_toml = r#"another_test = "abc""#;
        // Update agent
        let updated_agent = create_agent(
            1,
            "test_key",
            Kind::Piglet,
            Some(new_toml),
            Some(new_toml),
        );
        table.update(&agent, &updated_agent).unwrap();
        let retrieved_updated_agent = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(updated_agent, retrieved_updated_agent);

        // Delete agent
        table.delete(1, "test_key").unwrap();
        let result = table.get(1, "test_key").unwrap();
        assert!(result.is_none());
    }
}
