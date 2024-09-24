//! The `network` table.

use std::borrow::Cow;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use super::TableIter as TI;
use crate::{
    types::FromKeyValue, Agent, AgentConfig, AgentStatus, Indexable, Indexed, IndexedMap,
    IndexedMapUpdate, IndexedTable, Iterable, Map, Table as CrateTable, UniqueKey,
};

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Giganto {
    pub status: AgentStatus,
    pub draft: Option<AgentConfig>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct Node {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub giganto: Option<Giganto>,
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Update {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub giganto: Option<Giganto>,
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
            giganto: input.giganto,
        }
    }
}

impl<'i, 'n, 'j, 'k> Iterable<'i, TableIter<'n, 'j>> for Table<'n, 'k>
where
    'i: 'j,
{
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> TableIter<'n, 'j> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'n, 'j> {
        let iter = self.node.prefix_iter(direction, from, prefix);
        TableIter {
            node: iter,
            agent: self.agent.clone(),
        }
    }
}

pub struct Table<'n, 'd> {
    node: IndexedTable<'d, Inner>,
    agent: CrateTable<'n, 'd, Agent>,
}

impl<'n, 'd> Table<'n, 'd> {
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
        Some(Self { node, agent })
    }

    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        self.node.raw()
    }

    /// Returns the total count of nodes available.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count(&self) -> Result<usize> {
        self.node.count()
    }

    /// Returns a tuple of `(node, invalid_agents)` when node with `id` exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id(&self, id: u32) -> Result<Option<(Node, Vec<String>)>> {
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

        let node = Node {
            id: inner.id,
            name: inner.name,
            name_draft: inner.name_draft,
            profile: inner.profile,
            profile_draft: inner.profile_draft,
            agents,
            giganto: inner.giganto,
            creation_time: inner.creation_time,
        };
        Ok(Some((node, invalid_agents)))
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
            giganto: entry.giganto,
        };

        let node = self.node.put(inner)?;

        for mut agent in entry.agents {
            agent.node = node;
            self.agent.put(&agent)?;
        }
        Ok(node)
    }

    /// Removes a node with given `id`, returns `(key, invalid_agents)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.   
    pub fn remove(&self, id: u32) -> Result<(Vec<u8>, Vec<String>)> {
        use anyhow::anyhow;
        let inner = self.node.get_by_id(id)?.ok_or(anyhow!("No such id"))?;
        let mut invalids = vec![];
        for agent in inner.agents {
            if self.agent.delete(id, &agent).is_err() {
                invalids.push(agent);
            }
        }
        self.node.remove(id).map(|key| (key, invalids))
    }

    #[must_use]
    pub fn iter(&'d self, direction: Direction, from: Option<&[u8]>) -> TableIter<'n, 'd> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
        }
    }

    /// Updates the `Node` from `old` to `new` using the specified `id`. The `id` is used
    /// for the `Agent::node` field, meaning the `node` field of each agent in both `old.agents`
    /// and `new.agents` will be disregarded.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        use std::collections::HashMap;

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

        let old_inner = InnerUpdate {
            name: old.name.clone(),
            name_draft: old.name_draft.clone(),
            profile: old.profile.clone(),
            profile_draft: old.profile_draft.clone(),
            agents: old.agents.iter().map(|a| a.key.clone()).collect(),
            giganto: old.giganto.clone(),
        };

        let new_inner = InnerUpdate {
            name: new.name.clone(),
            name_draft: new.name_draft.clone(),
            profile: new.profile.clone(),
            profile_draft: new.profile_draft.clone(),
            agents: new.agents.iter().map(|a| a.key.clone()).collect(),
            giganto: new.giganto.clone(),
        };

        self.node.update(id, &old_inner, &new_inner)
    }
}

pub struct TableIter<'n, 'd> {
    node: TI<'d, Inner>,
    agent: CrateTable<'n, 'd, Agent>,
}

impl<'n, 'd> Iterator for TableIter<'n, 'd> {
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

                Node {
                    id: inner.id,
                    name: inner.name,
                    name_draft: inner.name_draft,
                    profile: inner.profile,
                    profile_draft: inner.profile_draft,
                    agents,
                    giganto: inner.giganto,
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
struct Inner {
    id: u32,
    name: String,
    name_draft: Option<String>,
    profile: Option<Profile>,
    profile_draft: Option<Profile>,
    creation_time: DateTime<Utc>,

    agents: Vec<String>,
    giganto: Option<Giganto>,
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
impl<'d> IndexedTable<'d, Inner> {
    /// Opens the `node` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    #[allow(dead_code)]
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .ok()
    }

    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        &self.indexed_map
    }

    /// Updates the `Node` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &InnerUpdate, new: &InnerUpdate) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

struct InnerUpdate {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<String>,
    pub giganto: Option<Giganto>,
}

impl From<Inner> for InnerUpdate {
    fn from(input: Inner) -> InnerUpdate {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            giganto: input.giganto,
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
        value.giganto.clone_from(&self.giganto);
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
        self.giganto == value.giganto
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::sync::Arc;

    use num_traits::ToPrimitive;

    use super::*;
    use crate::tables::agent::Config;
    use crate::AgentKind;
    use crate::AgentStatus;
    use crate::Store;

    type PortNumber = u16;

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Piglet {
        pub giganto_ip: Option<IpAddr>,
        pub giganto_port: Option<PortNumber>,
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
        pub giganto_ip: Option<IpAddr>,
        pub giganto_port: Option<PortNumber>,
        pub protocols: Option<Vec<String>>,

        pub sensors: Option<Vec<String>>,
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
    ) -> Node {
        let creation_time = Utc::now();
        Node {
            id,
            name: name.to_string(),
            name_draft: name_draft.map(|s| s.to_string()),
            profile,
            profile_draft,
            agents,
            creation_time,
            giganto: None,
        }
    }

    fn create_agents(
        node: u32,
        kinds: &[AgentKind],
        configs: &[Option<Config>],
        drafts: &[Option<Config>],
    ) -> Vec<Agent> {
        kinds
            .into_iter()
            .zip(configs)
            .zip(drafts)
            .map(|((kind, config), draft)| Agent {
                node,
                key: kind.to_u32().unwrap().to_string(),
                kind: *kind,
                status: AgentStatus::Enabled,
                config: config.clone(),
                draft: draft.clone(),
            })
            .collect()
    }

    fn create_configs(agents: &[AgentKind]) -> Vec<Option<Config>> {
        let ip = Some("127.0.0.1".parse::<IpAddr>().unwrap());
        let port = Some(1234);
        agents
            .iter()
            .map(|agent| match agent {
                AgentKind::Reconverge => Some("".to_string().try_into().unwrap()),
                AgentKind::Hog => {
                    let mut config = Hog::default();
                    config.giganto_ip = ip;
                    config.giganto_port = port;
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                AgentKind::Piglet => {
                    let mut config = Piglet::default();
                    config.giganto_ip = ip;
                    config.giganto_port = port;
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
            })
            .collect()
    }

    #[test]
    fn node_creation() {
        let kinds = vec![AgentKind::Reconverge, AgentKind::Piglet, AgentKind::Hog];
        let configs1: Vec<_> = create_configs(&kinds);
        let configs2 = vec![None, None, None];

        let profile = Profile::default();

        let agents = create_agents(1, &kinds, &configs1, &configs2);

        let node = create_node(1, "test", None, Some(profile), None, agents);
        assert_eq!(
            node.agents.into_iter().map(|a| a.key).collect::<Vec<_>>(),
            kinds
                .into_iter()
                .map(|k| k.to_u32().unwrap().to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn put_and_get() {
        let store = setup_store();

        let kinds = vec![AgentKind::Reconverge, AgentKind::Piglet, AgentKind::Hog];
        let configs1: Vec<_> = create_configs(&kinds);
        let configs2 = vec![None, None, None];

        let profile = Profile::default();

        let agents = create_agents(456, &kinds, &configs1, &configs2);

        let mut node = create_node(123, "test", None, Some(profile), None, agents);
        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);

        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_some());

        let (returned, invalid_agents) = res.unwrap();
        assert!(invalid_agents.is_empty());
        assert_eq!(returned, node);
    }

    #[test]
    fn remove() {
        let store = setup_store();

        let kinds = vec![AgentKind::Reconverge, AgentKind::Piglet, AgentKind::Hog];
        let configs1: Vec<_> = create_configs(&kinds);
        let configs2 = vec![None, None, None];

        let profile = Profile::default();

        let agents = create_agents(1, &kinds, &configs1, &configs2);

        let mut node = create_node(1, "test", None, None, Some(profile), agents);

        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);

        assert_eq!(node_table.count().unwrap(), 1);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 3);

        assert!(node_table.remove(node.id).is_ok());
        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_none());

        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
    }

    #[test]
    fn update() {
        let store = setup_store();
        let kinds = vec![AgentKind::Reconverge, AgentKind::Piglet, AgentKind::Hog];
        let configs1: Vec<_> = create_configs(&kinds);
        let configs2 = vec![None, None, None];

        let profile = Profile::default();

        let agents = create_agents(123, &kinds, &configs1, &configs2);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);

        let id = node.id;

        let update = Update {
            name: Some("test".to_string()),
            name_draft: Some("update".to_string()),
            profile: Some(profile.clone()),
            profile_draft: Some(profile.clone()),
            agents: agents[1..].into_iter().cloned().collect(),
            giganto: Some(Giganto::default()),
        };
        let old = node.clone().into();

        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid) = updated.unwrap();

        assert!(invalid.is_empty());

        node.name_draft = Some("update".to_string());
        node.profile = Some(profile.clone());
        node.profile_draft = Some(profile.clone());
        node.agents = node.agents.into_iter().skip(1).collect();
        node.giganto = Some(Giganto::default());

        assert_eq!(updated, node);
    }

    #[test]
    fn update_agents_drafts_only() {
        let store: Arc<Store> = setup_store();
        let kinds = vec![AgentKind::Reconverge, AgentKind::Hog];
        let configs1: Vec<_> = create_configs(&kinds);
        let configs2 = vec![None, None, None];

        let profile = Profile::default();

        let agents = create_agents(123, &kinds, &configs1, &configs2);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(node.clone());
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node = node.id);

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
            &[AgentKind::Piglet],
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
        let (updated, invalid) = updated.unwrap();
        assert!(invalid.is_empty());

        assert_eq!(updated.agents, update.agents);
    }
}
