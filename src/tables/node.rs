//! The `network` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{
    types::FromKeyValue, Agent, Indexable, Indexed, IndexedMap, IndexedMapUpdate, IndexedTable,
};

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

#[derive(Serialize, Deserialize)]
struct Review {
    pub port: Option<PortNumber>,
    pub web_port: Option<PortNumber>,
}

#[derive(Serialize, Deserialize)]
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
struct Reconverge {
    pub review_ip: Option<IpAddr>,
    pub review_port: Option<PortNumber>,
    pub giganto_ip: Option<IpAddr>,
    pub giganto_port: Option<PortNumber>,
}

#[derive(Serialize, Deserialize)]
struct Hog {
    pub review_ip: Option<IpAddr>,
    pub review_port: Option<PortNumber>,
    pub giganto_ip: Option<IpAddr>,
    pub giganto_port: Option<PortNumber>,
    pub protocols: bool,
    pub protocol_list: HashMap<String, bool>,

    pub sensors: bool,
    pub sensor_list: HashMap<String, bool>,
}

#[derive(Serialize, Deserialize)]
struct Piglet {
    pub giganto_ip: Option<IpAddr>,
    pub giganto_port: Option<PortNumber>,
    pub review_ip: Option<IpAddr>,
    pub review_port: Option<PortNumber>,
    pub save_packets: bool,
    pub http: bool,
    pub office: bool,
    pub exe: bool,
    pub pdf: bool,
    pub html: bool,
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

struct InnerNode {
    id: u32,
    name: String,
    customer_id: u32,
    description: String,
    hostname: String,
    creation_time: DateTime<Utc>,

    review: Option<Review>,
    giganto: Option<Giganto>,
    agents: Vec<u32>,
}

impl Node {
    fn into_storage(self) -> Result<(InnerNode, Vec<Agent>)> {
        use anyhow::anyhow;
        let settings = self.settings.ok_or(anyhow!("expecting settings"))?;
        let draft = self.settings_draft;
        let agents = settings.get_agents(self.id, draft)?;
        let inner = InnerNode {
            id: self.id,
            name: self.name,
            customer_id: settings.customer_id,
            description: settings.description,
            hostname: settings.hostname,
            creation_time: self.creation_time,
            review: None,
            giganto: None,
            agents: vec![],
        };

        Ok((inner, agents))
    }

    fn from_storage(inner: InnerNode, _agents: Vec<Agent>) -> Self {
        Self {
            id: inner.id,
            name: inner.name,
            name_draft: None,
            settings: None,
            settings_draft: None,
            creation_time: inner.creation_time,
        }
    }
}

impl Settings {
    fn get_agents(&self, node: u32, other: Option<Settings>) -> Result<Vec<Agent>> {
        let mut agents = vec![];
        let config = if self.piglet {
            let config = Piglet {
                giganto_ip: self.piglet_giganto_ip,
                giganto_port: self.piglet_giganto_port,
                review_ip: self.piglet_review_ip,
                review_port: self.piglet_review_port,
                save_packets: self.save_packets,
                http: self.http,
                office: self.office,
                exe: self.exe,
                pdf: self.pdf,
                html: self.html,
                txt: self.txt,
                smtp_eml: self.smtp_eml,
                ftp: self.ftp,
            };
            Some(toml::to_string(&config)?)
        } else {
            None
        };
        let draft = if let Some(other) = &other {
            if other.piglet {
                let draft = Piglet {
                    giganto_ip: other.piglet_giganto_ip,
                    giganto_port: other.piglet_giganto_port,
                    review_ip: other.piglet_review_ip,
                    review_port: other.piglet_review_port,
                    save_packets: other.save_packets,
                    http: other.http,
                    office: other.office,
                    exe: other.exe,
                    pdf: other.pdf,
                    html: other.html,
                    txt: other.txt,
                    smtp_eml: other.smtp_eml,
                    ftp: other.ftp,
                };
                Some(toml::to_string(&draft)?)
            } else {
                None
            }
        } else {
            None
        };
        let agent = Agent::new(
            node,
            "piglet".to_string(),
            "piglet".try_into()?,
            config,
            draft,
        )?;
        agents.push(agent);

        let config = if self.hog {
            let config = Hog {
                giganto_ip: self.hog_giganto_ip,
                giganto_port: self.hog_giganto_port,
                review_ip: self.hog_review_ip,
                review_port: self.hog_review_port,
                protocol_list: self.protocol_list.clone(),
                protocols: self.protocols,
                sensors: self.sensors,
                sensor_list: self.sensor_list.clone(),
            };
            Some(toml::to_string(&config)?)
        } else {
            None
        };
        let draft = if let Some(other) = &other {
            if other.hog {
                let draft = Hog {
                    giganto_ip: other.hog_giganto_ip,
                    giganto_port: other.hog_giganto_port,
                    review_ip: other.hog_review_ip,
                    review_port: other.hog_review_port,
                    protocol_list: other.protocol_list.clone(),
                    protocols: other.protocols,
                    sensors: other.sensors,
                    sensor_list: other.sensor_list.clone(),
                };
                Some(toml::to_string(&draft)?)
            } else {
                None
            }
        } else {
            None
        };
        let agent = Agent::new(node, "hog".to_string(), "hog".try_into()?, config, draft)?;
        agents.push(agent);

        let config = if self.reconverge {
            let config = Reconverge {
                giganto_ip: self.reconverge_giganto_ip,
                giganto_port: self.reconverge_giganto_port,
                review_ip: self.reconverge_review_ip,
                review_port: self.reconverge_review_port,
            };
            Some(toml::to_string(&config)?)
        } else {
            None
        };
        let draft = if let Some(other) = &other {
            if other.reconverge {
                let draft = Reconverge {
                    giganto_ip: other.reconverge_giganto_ip,
                    giganto_port: other.reconverge_giganto_port,
                    review_ip: other.reconverge_review_ip,
                    review_port: other.reconverge_review_port,
                };
                Some(toml::to_string(&draft)?)
            } else {
                None
            }
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
