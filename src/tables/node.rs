//! The `network` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use crate::{
    types::FromKeyValue, Agent, AgentKind, Indexable, Indexed, IndexedMap, IndexedMapUpdate,
    IndexedTable, Iterable, Map, Table as CrateTable,
};

use super::{agent::Config, TableIter as TI};

type PortNumber = u16;

#[derive(Clone, Serialize, Deserialize)]
struct Giganto {
    pub ingestion_ip: Option<IpAddr>,
    pub ingestion_port: Option<PortNumber>,
    pub publish_ip: Option<IpAddr>,
    pub publish_port: Option<PortNumber>,
    pub graphql_ip: Option<IpAddr>,
    pub graphql_port: Option<PortNumber>,
    pub retention_period: Option<u16>,
}

#[derive(Serialize, Deserialize)]
struct Hog {
    pub giganto_ip: Option<IpAddr>,
    pub giganto_port: Option<PortNumber>,
    pub protocols: Option<Vec<String>>,

    pub sensors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Clone, Deserialize, Serialize)]
pub struct Node {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub settings: Option<Settings>,
    pub settings_draft: Option<Settings>,
    pub creation_time: DateTime<Utc>,
}

pub struct Update {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub settings: Option<Settings>,
    pub settings_draft: Option<Settings>,
}

pub struct Table<'d> {
    node: IndexedTable<'d, InnerNode>,
    agent: CrateTable<'d, Agent>,
}

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
        Some(Self { node, agent })
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
        let mut settings: Option<Settings> = inner.settings.map(Into::into);
        let mut settings_draft: Option<Settings> = inner.settings_draft.map(Into::into);
        for agent in agents {
            if let Some(settings) = settings.as_mut() {
                settings.add_agent(agent.kind, agent.config.as_ref())?;
            }
            if let Some(settings_draft) = settings_draft.as_mut() {
                settings_draft.add_agent(agent.kind, agent.config.as_ref())?;
            }
        }
        let node = Node {
            id: inner.id,
            name: inner.name,
            name_draft: inner.name_draft,
            settings,
            settings_draft,
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
        let settings = entry.settings;
        let agents = settings.as_ref().map_or(Ok(vec![]), Settings::agents)?;
        let settings_draft = entry.settings_draft;
        let draft_agents = settings_draft
            .as_ref()
            .map_or(Ok(vec![]), Settings::agents)?;
        let mut agent_keys = vec![];
        for (agent, draft) in agents.into_iter().zip(draft_agents.into_iter()) {
            let agent = match (agent, draft) {
                (None, None) => continue,
                (Some(mut agent), Some(draft)) => {
                    agent.draft = draft.draft;
                    agent
                }
                (Some(agent), None) => agent,
                (None, Some(mut draft)) => {
                    std::mem::swap(&mut draft.config, &mut draft.draft);
                    draft
                }
            };
            self.agent.put(&agent)?;
            agent_keys.push(agent.key);
        }

        let inner = InnerNode {
            id: entry.id,
            name: entry.name,
            name_draft: entry.name_draft,
            settings: settings.map(Settings::into_inner),
            settings_draft: settings_draft.map(Settings::into_inner),
            creation_time: entry.creation_time,
            agents: agent_keys,
        };
        self.node.put(inner)
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
    pub fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
        }
    }

    /// Updates the `Node` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        let settings = old.settings.clone();
        let agents = settings.as_ref().map_or(Ok(vec![]), Settings::agents)?;
        let settings_draft = old.settings_draft.clone();
        let draft_agents = settings_draft
            .as_ref()
            .map_or(Ok(vec![]), Settings::agents)?;

        let old_agents: Vec<_> = agents
            .into_iter()
            .zip(draft_agents.into_iter())
            .map(|(agent, draft)| match (agent, draft) {
                (None, None) => None,
                (Some(mut agent), Some(draft)) => {
                    agent.draft = draft.draft;
                    Some(agent)
                }
                (Some(agent), None) => Some(agent),
                (None, Some(mut draft)) => {
                    std::mem::swap(&mut draft.config, &mut draft.draft);
                    Some(draft)
                }
            })
            .collect();

        let old_inner = InnerUpdate {
            name: old.name.clone(),
            name_draft: old.name_draft.clone(),
            settings: settings.map(Settings::into_inner),
            settings_draft: settings_draft.map(Settings::into_inner),
            agents: old_agents
                .iter()
                .filter_map(|a| a.as_ref().map(|a| a.key.clone()))
                .collect(),
        };

        let settings = new.settings.clone();
        let agents = settings.as_ref().map_or(Ok(vec![]), Settings::agents)?;
        let settings_draft = new.settings_draft.clone();
        let draft_agents = settings_draft
            .as_ref()
            .map_or(Ok(vec![]), Settings::agents)?;

        let new_agents: Vec<_> = agents
            .into_iter()
            .zip(draft_agents.into_iter())
            .map(|(agent, draft)| match (agent, draft) {
                (None, None) => None,
                (Some(mut agent), Some(draft)) => {
                    agent.draft = draft.draft;
                    Some(agent)
                }
                (Some(agent), None) => Some(agent),
                (None, Some(mut draft)) => {
                    std::mem::swap(&mut draft.config, &mut draft.draft);
                    Some(draft)
                }
            })
            .collect();
        let new_inner = InnerUpdate {
            name: new.name.clone(),
            name_draft: new.name_draft.clone(),
            settings: settings.map(Settings::into_inner),
            settings_draft: settings_draft.map(Settings::into_inner),
            agents: new_agents
                .iter()
                .filter_map(|a| a.as_ref().map(|a| a.key.clone()))
                .collect(),
        };

        for (old, new) in old_agents.into_iter().zip(new_agents.into_iter()) {
            match (old, new) {
                (None, None) => {}
                (Some(old), None) => self.agent.delete(id, &old.key)?,
                (None, Some(new)) => {
                    self.agent.put(&new)?;
                }
                (Some(old), Some(new)) => {
                    if old != new {
                        self.agent.update(&old, &new)?;
                    }
                }
            }
        }
        self.node.update(id, &old_inner, &new_inner)
    }
}

pub struct TableIter<'d> {
    node: TI<'d, InnerNode>,
    agent: CrateTable<'d, Agent>,
}

impl<'d> Iterator for TableIter<'d> {
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
                let mut settings: Option<Settings> = inner.settings.map(Into::into);
                let mut settings_draft: Option<Settings> = inner.settings_draft.map(Into::into);
                for agent in agents {
                    if let Some(settings) = settings.as_mut() {
                        settings
                            .add_agent(agent.kind, agent.config.as_ref())
                            .expect("invalid agent config");
                    }
                    if let Some(settings_draft) = settings_draft.as_mut() {
                        settings_draft
                            .add_agent(agent.kind, agent.config.as_ref())
                            .expect("invalid agent config");
                    }
                }
                Node {
                    id: inner.id,
                    name: inner.name,
                    name_draft: inner.name_draft,
                    settings,
                    settings_draft,
                    creation_time: inner.creation_time,
                }
            })
        })
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
struct InnerSettings {
    customer_id: u32,
    description: String,
    hostname: String,

    giganto: Option<Giganto>,
}

#[derive(Clone, Deserialize, Serialize)]
struct InnerNode {
    id: u32,
    name: String,
    name_draft: Option<String>,
    settings: Option<InnerSettings>,
    settings_draft: Option<InnerSettings>,
    creation_time: DateTime<Utc>,

    agents: Vec<String>,
}

impl Settings {
    fn into_inner(self) -> InnerSettings {
        
        let giganto = if self.giganto {
            Some(Giganto {
                ingestion_ip: self.giganto_ingestion_ip,
                ingestion_port: self.giganto_ingestion_port,
                publish_ip: self.giganto_publish_ip,
                publish_port: self.giganto_publish_port,
                graphql_ip: self.giganto_graphql_ip,
                graphql_port: self.giganto_graphql_port,
                retention_period: self.retention_period,
            })
        } else {
            None
        };
        InnerSettings {
            customer_id: self.customer_id,
            description: self.description,
            hostname: self.hostname,
            giganto,
        }
    }

    fn add_agent(&mut self, kind: AgentKind, config: Option<&Config>) -> Result<()> {
        match kind {
            AgentKind::Reconverge => {
                if let Some(config) = config {
                    self.reconverge = true;
                    
                }
            }
            AgentKind::Piglet => {
                if let Some(config) = config {
                    let config: Piglet = toml::from_str(config.as_ref())?;
                    self.piglet = true;
                    self.piglet_giganto_ip = config.giganto_ip;
                    self.piglet_giganto_port = config.giganto_port;
                    self.piglet_review_ip = config.review_ip;
                    self.piglet_review_port = config.review_port;
                }
            }
            AgentKind::Hog => {
                if let Some(config) = config {
                    let config: Hog = toml::from_str(config.as_ref())?;
                    self.hog = true;
                    self.hog_giganto_ip = config.giganto_ip;
                    self.hog_giganto_port = config.giganto_port;
                    self.hog_review_ip = config.review_ip;
                    self.hog_review_port = config.review_port;
                }
            }
        }
        Ok(())
    }

    fn agents(&self) -> Result<Vec<Option<Agent>>> {
        let node = u32::MAX;
        let draft = None;

        let mut agents = vec![];
        if self.piglet {
            let config = Piglet {
                giganto_ip: self.piglet_giganto_ip,
                giganto_port: self.piglet_giganto_port,
                save_packets: self.save_packets,
                http: self.http,
                office: self.office,
                exe: self.exe,
                pdf: self.pdf,
                vbs: self.vbs,
                txt: self.txt,
                smtp_eml: self.smtp_eml,
                ftp: self.ftp,
            };
            let agent = Agent::new(
                node,
                "piglet".to_string(),
                "piglet".try_into()?,
                Some(toml::to_string(&config)?),
                draft.clone(),
            )?;
            agents.push(Some(agent));
        } else {
            agents.push(None);
        }

        if self.hog {
            let config = Hog {
                giganto_ip: self.hog_giganto_ip,
                giganto_port: self.hog_giganto_port,
                protocols: self.protocols.clone(),
                sensors: self.sensors.clone(),
            };
            let agent = Agent::new(
                node,
                "hog".to_string(),
                "hog".try_into()?,
                Some(toml::to_string(&config)?),
                draft.clone(),
            )?;
            agents.push(Some(agent));
        } else {
            agents.push(None);
        }

        if self.reconverge {

            let agent = Agent::new(
                node,
                "reconverge".to_string(),
                "reconverge".try_into()?,
                Some("".to_string()),
                draft.clone(),
            )?;
            agents.push(Some(agent));
        } else {
            agents.push(None);
        }

        Ok(agents)
    }
}

impl From<InnerSettings> for Settings {
    fn from(inner: InnerSettings) -> Self {
        let mut settings = Settings {
            customer_id: inner.customer_id,
            description: inner.description,
            hostname: inner.hostname,
            ..Default::default()
        };

        if let Some(giganto) = inner.giganto {
            settings.giganto = true;
            settings.giganto_graphql_ip = giganto.graphql_ip;
            settings.giganto_graphql_port = giganto.graphql_port;
            settings.giganto_ingestion_ip = giganto.ingestion_ip;
            settings.giganto_ingestion_port = giganto.ingestion_port;
            settings.giganto_publish_ip = giganto.publish_ip;
            settings.giganto_publish_port = giganto.publish_port;
        }
        settings
    }
}

impl FromKeyValue for InnerNode {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl Indexable for InnerNode {
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
impl<'d> IndexedTable<'d, InnerNode> {
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
    pub settings: Option<InnerSettings>,
    pub settings_draft: Option<InnerSettings>,
    pub agents: Vec<String>,
}

impl From<InnerNode> for InnerUpdate {
    fn from(input: InnerNode) -> InnerUpdate {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            settings: input.settings,
            settings_draft: input.settings_draft,
            agents: input.agents,
        }
    }
}

impl IndexedMapUpdate for InnerUpdate {
    type Entry = InnerNode;

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
        value.agents.clone_from(&self.agents);
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
        if self.settings_draft != value.settings_draft {
            return false;
        }
        self.agents == value.agents
    }
}

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
