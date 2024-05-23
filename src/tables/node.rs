//! The `network` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{
    types::FromKeyValue, Agent, AgentKind, Indexable, IndexedMap, IndexedMapUpdate,
    IndexedTable, Map, Table,
};

use super::agent::Config;

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
pub struct NodeTable<'d> {
    node: IndexedTable<'d, InnerNode>,
    agent: Table<'d, Agent>,
}

impl<'d> NodeTable<'d> {
    pub fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let node = IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .expect("{super::NODES} must be present");
        let agent = Map::open(db, super::AGENTS).map(Table::new)?;
        Some(Self { node, agent })
    }

    pub fn count(&self) -> Result<usize> {
        self.node.count()
    }

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

        // agent + innter_settings + inner_draft_settings -> settings + draft_settings
        Ok(None)
    }
}

#[derive(Clone, Deserialize, Serialize)]
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

    fn add_agent(&mut self, kind: AgentKind, config: Option<Config>) -> Result<()> {
        match kind {
            AgentKind::Reconverge => {}
            AgentKind::Piglet => {}
            AgentKind::Hog => {}
        }
        Ok(())
    }

    fn agents(&self) -> Result<Vec<Agent>> {
        let node = u32::MAX;
        let draft = None;

        let mut agents = vec![];
        let config = if self.piglet {
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
            Some(toml::to_string(&config)?)
        } else {
            None
        };

        let agent = Agent::new(
            node,
            "piglet".to_string(),
            "piglet".try_into()?,
            config,
            draft.clone(),
        )?;
        agents.push(agent);

        let config = if self.hog {
            let config = Hog {
                giganto_ip: self.hog_giganto_ip,
                giganto_port: self.hog_giganto_port,
                protocols: self.protocols.clone(),
                sensors: self.sensors.clone(),
            };
            Some(toml::to_string(&config)?)
        } else {
            None
        };

        let agent = Agent::new(
            node,
            "hog".to_string(),
            "hog".try_into()?,
            config,
            draft.clone(),
        )?;
        agents.push(agent);

        let config = if self.reconverge {
            Some("".to_string())
        } else {
            None
        };

        let agent = Agent::new(
            node,
            "reconverge".to_string(),
            "reconverge".try_into()?,
            config,
            draft,
        )?;
        agents.push(agent);

        Ok(agents)
    }
}

impl From<InnerSettings> for Settings {
    fn from(inner: InnerSettings) -> Self {
        let mut settings = Self::default();
        settings.customer_id = inner.customer_id;
        settings.description = inner.description;
        settings.hostname = inner.hostname;

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
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .ok()
    }

    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        &self.indexed_map
    }

    // /// Updates the `Node` from `old` to `new`, given `id`.
    // ///
    // /// # Errors
    // ///
    // /// Returns an error if the `id` is invalid or the database operation fails.
    // pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
    //     self.indexed_map.update(id, old, new)
    // }
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
