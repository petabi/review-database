//! The `network` table.

use std::{borrow::Cow, fmt::Display};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::TableIter as TI;
use crate::{
    Agent, Indexable, Indexed, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable, Map, Remote,
    Table as CrateTable, UniqueKey, types::FromKeyValue,
};

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
    Unsupervised = 1,
    Sensor = 2,
    SemiSupervised = 3,
    TimeSeriesGenerator = 4,
    Datalake = 5,
    TiContainer = 6,
}

#[derive(
    Serialize,
    Default,
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
#[repr(u8)]
#[strum(serialize_all = "snake_case")]
pub enum Status {
    Disabled = 0,
    #[default]
    Enabled = 1,
    ReloadFailed = 2,
    Unknown = u8::MAX,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default)]
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

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct Node {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub remotes: Vec<Remote>,
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Update {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub remotes: Vec<Remote>,
}

impl UniqueKey for Node {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl From<Node> for Update {
    fn from(input: Node) -> Self {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            remotes: input.remotes,
        }
    }
}

impl<'i, 'j> Iterable<'i, TableIter<'j>> for Table<'_>
where
    'i: 'j,
{
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> TableIter<'j> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
            remote: self.remote.clone(),
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'j> {
        let iter = self.node.prefix_iter(direction, from, prefix);
        TableIter {
            node: iter,
            agent: self.agent.clone(),
            remote: self.remote.clone(),
        }
    }
}

pub struct Table<'d> {
    node: IndexedTable<'d, Inner>,
    agent: CrateTable<'d, Agent>,
    remote: CrateTable<'d, Remote>,
}

type NodeWithInvalidAgentRemote = (Node, Vec<String>, Vec<String>);

impl<'d> Table<'d> {
    /// Opens the node table in the database.
    ///
    /// Returns `None` if the table does not exist.
    ///
    /// # Panics
    ///
    /// Panics if node map doesn't exist.
    pub fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let node = IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .expect("{super::NODES} must be present");
        let agent = Map::open(db, super::AGENTS).map(CrateTable::new)?;
        let remote = Map::open(db, super::REMOTES).map(CrateTable::new)?;
        Some(Self {
            node,
            agent,
            remote,
        })
    }

    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        self.node.raw()
    }

    pub(crate) fn agent_raw(&self) -> &Map<'_> {
        self.agent.raw()
    }

    pub(crate) fn remote_raw(&self) -> &Map<'_> {
        self.remote.raw()
    }

    /// Returns the total count of nodes available.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count(&self) -> Result<usize> {
        self.node.count()
    }

    /// Returns a tuple of `(node, invalid_agents, invalid_remotes)` when node with `id` exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id(&self, id: u32) -> Result<Option<NodeWithInvalidAgentRemote>> {
        let Some(inner) = self.node.get_by_id(id)? else {
            return Ok(None);
        };

        let mut agents = vec![];
        let mut invalid_agents = vec![];
        for aid in inner.agents {
            if let Some(agent) = self.agent.get(id, &aid)? {
                agents.push(agent);
            } else {
                invalid_agents.push(aid);
            }
        }

        let mut remotes = vec![];
        let mut invalid_remotes = vec![];
        for rid in inner.remotes {
            if let Some(remote) = self.remote.get(id, &rid)? {
                remotes.push(remote);
            } else {
                invalid_remotes.push(rid);
            }
        }

        let node = Node {
            id: inner.id,
            name: inner.name,
            name_draft: inner.name_draft,
            profile: inner.profile,
            profile_draft: inner.profile_draft,
            agents,
            remotes,
            creation_time: inner.creation_time,
        };
        Ok(Some((node, invalid_agents, invalid_remotes)))
    }

    /// Inserts a node entry, returns the `id` of the inserted node.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, entry: Node) -> Result<u32> {
        let inner = Inner {
            id: entry.id,
            name: entry.name,
            name_draft: entry.name_draft,
            profile: entry.profile,
            profile_draft: entry.profile_draft,
            creation_time: entry.creation_time,
            agents: entry.agents.iter().map(|a| a.key.clone()).collect(),
            remotes: entry.remotes.iter().map(|a| a.key.clone()).collect(),
        };

        let node = self.node.put(inner)?;

        for mut agent in entry.agents {
            agent.node = node;
            self.agent.put(&agent)?;
        }

        for mut remote in entry.remotes {
            remote.node = node;
            self.remote.put(&remote)?;
        }
        Ok(node)
    }

    /// Removes a node with given `id`, returns `(key, invalid_agents, invalid_remotes)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, id: u32) -> Result<(Vec<u8>, Vec<String>, Vec<String>)> {
        use anyhow::anyhow;
        let inner = self.node.get_by_id(id)?.ok_or(anyhow!("No such id"))?;
        let mut invalid_agents = vec![];
        for agent in inner.agents {
            if self.agent.delete(id, &agent).is_err() {
                invalid_agents.push(agent);
            }
        }

        let mut invalid_remotes = vec![];
        for remote in inner.remotes {
            if self.remote.delete(id, &remote).is_err() {
                invalid_remotes.push(remote);
            }
        }
        self.node
            .remove(id)
            .map(|key| (key, invalid_agents, invalid_remotes))
    }

    #[must_use]
    pub fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
            remote: self.remote.clone(),
        }
    }

    /// Updates the `Node` from `old` to `new` using the specified `id`. The `id` is used for both
    /// the `Agent::node` and `Remote::node` fields, meaning the `node` field of each agent in both
    /// `old.agents` and `new.agents`, as well as each remote in both `old.remotes` and
    /// `new.remotes`, will be disregarded.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        use std::collections::HashMap;

        // Update Agent
        let mut old_agents: HashMap<_, _> = old.agents.iter().map(|a| (&a.key, a)).collect();
        let mut new_agents: HashMap<_, _> = new.agents.iter().map(|a| (&a.key, a)).collect();

        for to_remove in old_agents.keys().filter(|k| !new_agents.contains_key(*k)) {
            self.agent.delete(id, to_remove)?;
        }
        old_agents.retain(|&k, _| new_agents.contains_key(k));

        for (_k, to_insert) in new_agents
            .iter()
            .filter(|(k, _v)| !old_agents.contains_key(*k))
        {
            let mut to_insert: Agent = (*to_insert).clone();
            to_insert.node = id;
            self.agent.put(&to_insert)?;
        }
        new_agents.retain(|&k, _| old_agents.contains_key(k));

        let mut old_agents: Vec<_> = old_agents.values().collect();
        old_agents.sort_unstable_by_key(|a| a.key.clone());
        let mut new_agents: Vec<_> = new_agents.values().collect();
        new_agents.sort_unstable_by_key(|a| a.key.clone());
        for (old, new) in old_agents
            .into_iter()
            .zip(new_agents)
            .filter(|(o, n)| **o != **n)
        {
            let mut old = (*old).clone();
            old.node = id;
            let mut new = (*new).clone();
            new.node = id;
            self.agent.update(&old, &new)?;
        }

        // Update Remote
        let mut old_remotes: HashMap<_, _> = old.remotes.iter().map(|a| (&a.key, a)).collect();
        let mut new_remotes: HashMap<_, _> = new.remotes.iter().map(|a| (&a.key, a)).collect();

        for to_remove in old_remotes.keys().filter(|k| !new_remotes.contains_key(*k)) {
            self.remote.delete(id, to_remove)?;
        }
        old_remotes.retain(|&k, _| new_remotes.contains_key(k));

        for (_k, to_insert) in new_remotes
            .iter()
            .filter(|(k, _v)| !old_remotes.contains_key(*k))
        {
            let mut to_insert: Remote = (*to_insert).clone();
            to_insert.node = id;
            self.remote.put(&to_insert)?;
        }
        new_remotes.retain(|&k, _| old_remotes.contains_key(k));

        let mut old_remotes: Vec<_> = old_remotes.values().collect();
        old_remotes.sort_unstable_by_key(|a| a.key.clone());
        let mut new_remotes: Vec<_> = new_remotes.values().collect();
        new_remotes.sort_unstable_by_key(|a| a.key.clone());
        for (old, new) in old_remotes
            .into_iter()
            .zip(new_remotes)
            .filter(|(o, n)| **o != **n)
        {
            let mut old = (*old).clone();
            old.node = id;
            let mut new = (*new).clone();
            new.node = id;
            self.remote.update(&old, &new)?;
        }

        // Update Node
        let old_inner = InnerUpdate {
            name: old.name.clone(),
            name_draft: old.name_draft.clone(),
            profile: old.profile.clone(),
            profile_draft: old.profile_draft.clone(),
            agents: old.agents.iter().map(|a| a.key.clone()).collect(),
            remotes: old.remotes.iter().map(|a| a.key.clone()).collect(),
        };

        let new_inner = InnerUpdate {
            name: new.name.clone(),
            name_draft: new.name_draft.clone(),
            profile: new.profile.clone(),
            profile_draft: new.profile_draft.clone(),
            agents: new.agents.iter().map(|a| a.key.clone()).collect(),
            remotes: new.remotes.iter().map(|a| a.key.clone()).collect(),
        };

        self.node.update(id, &old_inner, &new_inner)
    }

    /// Updates the status of an agent specified by `agent_key`, which belongs to the node whose
    /// hostname matches the given `hostname`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An error occurs while iterating over nodes.
    /// - No node exists with a profile matching the given `hostname`.
    /// - No agent exists with the given `agent_key`.
    /// - The database operation fails.
    pub fn update_agent_status_by_hostname(
        &mut self,
        hostname: &str,
        agent_key: &str,
        new_status: Status,
    ) -> Result<()> {
        let mut target_node = None;
        for result in self.iter(Direction::Forward, None) {
            let node = result.context("Failed to iterate over nodes")?;
            if node
                .profile
                .as_ref()
                .is_some_and(|p| p.hostname == hostname)
            {
                target_node = Some(node);
                break;
            }
        }
        let node =
            target_node.ok_or_else(|| anyhow::anyhow!("No node found for hostname: {hostname}"))?;

        let agent = node
            .agents
            .iter()
            .find(|agent| agent.key == agent_key)
            .ok_or_else(|| {
                anyhow::anyhow!("No agent found with key: {agent_key} for hostname: {hostname}")
            })?;
        let mut updated_agent = agent.clone();
        updated_agent.status = new_status;
        self.agent.update(agent, &updated_agent)
    }
}

pub struct TableIter<'d> {
    node: TI<'d, Inner>,
    agent: CrateTable<'d, Agent>,
    remote: CrateTable<'d, Remote>,
}

impl Iterator for TableIter<'_> {
    type Item = Result<Node, anyhow::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.node.next().map(|res| {
            res.map(|inner| {
                let mut agents = vec![];
                for aid in inner.agents {
                    if let Ok(Some(agent)) = self.agent.get(inner.id, &aid) {
                        agents.push(agent);
                    }
                }

                let mut remotes = vec![];
                for rid in inner.remotes {
                    if let Ok(Some(remote)) = self.remote.get(inner.id, &rid) {
                        remotes.push(remote);
                    }
                }

                Node {
                    id: inner.id,
                    name: inner.name,
                    name_draft: inner.name_draft,
                    profile: inner.profile,
                    profile_draft: inner.profile_draft,
                    agents,
                    remotes,
                    creation_time: inner.creation_time,
                }
            })
        })
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug, Default)]
pub struct Profile {
    pub customer_id: u32,
    pub description: String,
    pub hostname: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Inner {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub creation_time: DateTime<Utc>,
    pub agents: Vec<String>,
    pub remotes: Vec<String>,
}

impl FromKeyValue for Inner {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl Indexable for Inner {
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
impl IndexedTable<'_, Inner> {
    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        &self.indexed_map
    }

    /// Updates the `Node` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    fn update(&mut self, id: u32, old: &InnerUpdate, new: &InnerUpdate) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

struct InnerUpdate {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<String>,
    pub remotes: Vec<String>,
}

impl From<Inner> for InnerUpdate {
    fn from(input: Inner) -> InnerUpdate {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            remotes: input.remotes,
        }
    }
}

impl IndexedMapUpdate for InnerUpdate {
    type Entry = Inner;

    fn key(&self) -> Option<Cow<[u8]>> {
        self.name.as_deref().map(|n| Cow::Borrowed(n.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(n) = self.name.as_deref() {
            n.clone_into(&mut value.name);
        }
        value.name_draft.clone_from(&self.name_draft);
        value.profile.clone_from(&self.profile);
        value.profile_draft.clone_from(&self.profile_draft);
        value.agents.clone_from(&self.agents);
        value.remotes.clone_from(&self.remotes);
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
        if self.profile != value.profile {
            return false;
        }
        if self.profile_draft != value.profile_draft {
            return false;
        }
        if self.agents != value.agents {
            return false;
        }
        self.remotes == value.remotes
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::Arc,
    };

    use num_traits::ToPrimitive;

    use super::*;
    use crate::Store;

    type PortNumber = u16;

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Piglet {
        pub datalake_ip: Option<IpAddr>,
        pub datalake_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub vbs: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,
    }

    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Hog {
        pub datalake_ip: Option<IpAddr>,
        pub datalake_port: Option<PortNumber>,
        pub protocols: Option<Vec<String>>,

        pub sensors: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Datalake {
        pub datalake_addr: SocketAddr,
        pub ack_transmission: u16,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TiContainer {
        pub ti_container_graphql_addr: SocketAddr,
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_node(
        id: u32,
        name: &str,
        name_draft: Option<&str>,
        profile: Option<Profile>,
        profile_draft: Option<Profile>,
        agents: Vec<Agent>,
        remotes: Vec<Remote>,
    ) -> Node {
        let creation_time = Utc::now();
        Node {
            id,
            name: name.to_string(),
            name_draft: name_draft.map(ToString::to_string),
            profile,
            profile_draft,
            agents,
            remotes,
            creation_time,
        }
    }

    fn create_agents(
        node: u32,
        kinds: &[Kind],
        configs: &[Option<Config>],
        drafts: &[Option<Config>],
    ) -> Vec<Agent> {
        kinds
            .iter()
            .zip(configs)
            .zip(drafts)
            .map(|((kind, config), draft)| Agent {
                node,
                key: kind.to_u32().unwrap().to_string(),
                kind: *kind,
                status: Status::Enabled,
                config: config.clone(),
                draft: draft.clone(),
            })
            .collect()
    }

    fn create_remotes(node: u32, kinds: &[Kind], drafts: &[Option<Config>]) -> Vec<Remote> {
        kinds
            .iter()
            .zip(drafts)
            .map(|(kind, draft)| Remote {
                node,
                key: kind.to_u32().unwrap().to_string(),
                kind: *kind,
                status: Status::Enabled,
                draft: draft.clone(),
            })
            .collect()
    }

    fn create_configs(kinds: &[Kind]) -> Vec<Option<Config>> {
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let datalake_port = 1234;
        let ti_container_port = 4567;

        kinds
            .iter()
            .map(|kind| match kind {
                Kind::SemiSupervised => {
                    let config = Hog {
                        datalake_ip: Some(ip),
                        datalake_port: Some(datalake_port),
                        ..Default::default()
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                Kind::Sensor => {
                    let config = Piglet {
                        datalake_ip: Some(ip),
                        datalake_port: Some(datalake_port),
                        ..Default::default()
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                Kind::TimeSeriesGenerator | Kind::Unsupervised => {
                    Some(String::new().try_into().unwrap())
                }
                Kind::Datalake => {
                    let config = Datalake {
                        datalake_addr: SocketAddr::new(ip, datalake_port),
                        ack_transmission: 1000,
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                Kind::TiContainer => {
                    let config = TiContainer {
                        ti_container_graphql_addr: SocketAddr::new(ip, ti_container_port),
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
            })
            .collect()
    }

    #[test]
    fn node_creation() {
        let agent_kinds = vec![
            Kind::Unsupervised,
            Kind::Sensor,
            Kind::SemiSupervised,
            Kind::TimeSeriesGenerator,
        ];
        let agent_configs1 = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None, None];
        let profile = Profile::default();
        let agents = create_agents(1, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(1, &remote_kinds, &remote_config);

        let node = create_node(1, "test", None, Some(profile), None, agents, remotes);
        assert_eq!(
            node.agents.into_iter().map(|a| a.key).collect::<Vec<_>>(),
            agent_kinds
                .into_iter()
                .map(|k| k.to_u32().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            node.remotes.into_iter().map(|a| a.key).collect::<Vec<_>>(),
            remote_kinds
                .into_iter()
                .map(|k| k.to_u32().unwrap().to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn put_and_get() {
        let store = setup_store();

        let agent_kinds = vec![Kind::Unsupervised, Kind::Sensor, Kind::SemiSupervised];
        let agent_configs1: Vec<_> = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(456, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(456, &remote_kinds, &remote_config);

        let mut node = create_node(123, "test", None, Some(profile), None, agents, remotes);
        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);
        node.remotes.iter_mut().for_each(|a| a.node = node.id);

        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_some());

        let (returned, invalid_agents, invalid_remotes) = res.unwrap();
        assert!(invalid_agents.is_empty());
        assert!(invalid_remotes.is_empty());
        assert_eq!(returned, node);
    }

    #[test]
    fn remove() {
        let store = setup_store();

        let agent_kinds = vec![Kind::Unsupervised, Kind::Sensor, Kind::SemiSupervised];
        let agent_configs1: Vec<_> = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(1, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(1, &remote_kinds, &remote_config);

        let mut node = create_node(1, "test", None, None, Some(profile), agents, remotes);

        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
        assert_eq!(
            store.remotes_map().iter(Direction::Forward, None).count(),
            0
        );
        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);
        node.remotes.iter_mut().for_each(|a| a.node = node.id);

        assert_eq!(node_table.count().unwrap(), 1);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 3);
        assert_eq!(
            store.remotes_map().iter(Direction::Forward, None).count(),
            2
        );

        assert!(node_table.remove(node.id).is_ok());
        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_none());

        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
        assert_eq!(
            store.remotes_map().iter(Direction::Forward, None).count(),
            0
        );
    }

    #[test]
    fn update() {
        let store = setup_store();

        let agent_kinds = vec![Kind::Unsupervised, Kind::Sensor, Kind::SemiSupervised];
        let agent_configs1: Vec<_> = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(123, &remote_kinds, &remote_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            remotes.clone(),
        );
        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);
        node.remotes.iter_mut().for_each(|a| a.node = node.id);

        let id = node.id;

        let update = Update {
            name: Some("test".to_string()),
            name_draft: Some("update".to_string()),
            profile: Some(profile.clone()),
            profile_draft: Some(profile.clone()),
            agents: agents[1..].to_vec(),
            remotes: remotes[1..].to_vec(),
        };
        let old = node.clone().into();

        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_remotes) = updated.unwrap();

        assert!(invalid_agents.is_empty());
        assert!(invalid_remotes.is_empty());

        node.name_draft = Some("update".to_string());
        node.profile = Some(profile.clone());
        node.profile_draft = Some(profile.clone());
        node.agents = node.agents.into_iter().skip(1).collect();
        node.remotes = node.remotes.into_iter().skip(1).collect();

        assert_eq!(updated, node);
    }

    #[test]
    fn update_agents_drafts_only() {
        let store: Arc<Store> = setup_store();

        let agent_kinds = vec![Kind::Unsupervised, Kind::SemiSupervised];
        let agent_configs1: Vec<_> = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(123, &remote_kinds, &remote_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            remotes.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);
        node.remotes.iter_mut().for_each(|a| a.node = node.id);

        let id = node.id;

        let old = node.clone().into();
        let mut update = node.clone();
        let mut update_agents: Vec<_> = update
            .agents
            .into_iter()
            .skip(1) // remove Reconverge
            .map(|mut a| {
                // update draft of Hog
                a.draft = Some("my_key=10".to_string().try_into().unwrap());
                a
            })
            .collect();
        update_agents.extend(create_agents(
            id,
            &[Kind::Sensor],
            &[Some(
                toml::to_string(&Piglet::default())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )],
            &[Some("my_key=10".to_string().try_into().unwrap())],
        )); // Add Piglet
        update.agents = update_agents;

        let update = update.into();
        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_remotes) = updated.unwrap();
        assert!(invalid_agents.is_empty());
        assert!(invalid_remotes.is_empty());

        assert_eq!(updated.agents, update.agents);
    }

    #[test]
    fn update_agent_status_by_hostname() {
        let store = setup_store();
        let kinds = vec![Kind::Sensor, Kind::SemiSupervised];
        let configs: Vec<_> = create_configs(&kinds);

        let profile = Profile {
            hostname: "test-hostname".to_string(),
            ..Default::default()
        };

        let agents = create_agents(456, &kinds, &configs, &configs);

        let mut node = create_node(
            456,
            "test",
            Some("test"),
            Some(profile.clone()),
            Some(profile.clone()),
            agents.clone(),
            vec![],
        );

        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);

        let id = node.id;

        assert!(
            node_table
                .update_agent_status_by_hostname(
                    "test-hostname",
                    "3", // The agent key of `Kind::SemiSupervised` was set to "3" in `create_agents`.
                    Status::Disabled
                )
                .is_ok()
        );

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid, _) = updated.unwrap();
        assert!(invalid.is_empty());

        // Check that the status of the `Kind::Sensor` agent was not updated.
        assert_eq!(updated.agents[0].status, Status::Enabled);

        // Check that the status of the `Kind::SemiSupervised` agent was updated.
        assert_eq!(updated.agents[1].status, Status::Disabled);
    }

    #[test]
    fn update_remotes_draft() {
        let store: Arc<Store> = setup_store();

        let agent_kinds = vec![Kind::Unsupervised, Kind::SemiSupervised];
        let agent_configs1: Vec<_> = create_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let remote_kinds = vec![Kind::Datalake, Kind::TiContainer];
        let remote_config = create_configs(&remote_kinds);
        let remotes = create_remotes(123, &remote_kinds, &remote_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            remotes.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);
        node.remotes.iter_mut().for_each(|a| a.node = node.id);

        let id = node.id;

        let old = node.clone().into();
        let mut update = node.clone();
        let update_remotes: Vec<_> = update
            .remotes
            .into_iter()
            .skip(1) // remove Reconverge
            .map(|mut a| {
                // update draft of ti container
                a.draft = Some("my_key=10".to_string().try_into().unwrap());
                a
            })
            .collect();
        update.remotes = update_remotes;

        let update = update.into();
        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_remotes) = updated.unwrap();
        assert!(invalid_agents.is_empty());
        assert!(invalid_remotes.is_empty());

        assert_eq!(updated.remotes, update.remotes);
    }
}
