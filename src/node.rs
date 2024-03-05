use bincode::Options;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, net::IpAddr};

use crate::{types::FromKeyValue, Indexable};

type PortNumber = u16;

#[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct NodeSetting {
    pub name: String,
    pub customer_id: u32,
    pub description: String,
    pub hostname: String,

    pub review: bool,
    pub review_port: Option<PortNumber>,
    pub review_web_port: Option<PortNumber>,

    pub piglet: bool,
    pub piglet_giganto_ip: Option<IpAddr>,
    pub piglet_giganto_port: Option<PortNumber>,
    pub piglet_review_ip: Option<IpAddr>,
    pub piglet_review_port: Option<PortNumber>,
    pub save_packets: bool,
    pub http: bool,
    pub office: bool,
    pub exe: bool,
    pub pdf: bool,
    pub html: bool,
    pub txt: bool,
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
    pub reconverge_review_ip: Option<IpAddr>,
    pub reconverge_review_port: Option<PortNumber>,
    pub reconverge_giganto_ip: Option<IpAddr>,
    pub reconverge_giganto_port: Option<PortNumber>,

    pub hog: bool,
    pub hog_review_ip: Option<IpAddr>,
    pub hog_review_port: Option<PortNumber>,
    pub hog_giganto_ip: Option<IpAddr>,
    pub hog_giganto_port: Option<PortNumber>,
    pub protocols: bool,
    pub protocol_list: HashMap<String, bool>,

    pub sensors: bool,
    pub sensor_list: HashMap<String, bool>,
}

#[derive(Deserialize, Serialize)]
pub struct Node {
    pub id: u32,
    pub creation_time: DateTime<Utc>,
    pub as_is: Option<NodeSetting>,
    pub to_be: Option<NodeSetting>,
}

impl FromKeyValue for Node {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::DefaultOptions::new().deserialize(value)?)
    }
}

impl Indexable for Node {
    fn key(&self) -> Cow<[u8]> {
        if let Some(as_is) = &self.as_is {
            Cow::from(as_is.name.as_bytes())
        } else if let Some(to_be) = &self.to_be {
            Cow::from(to_be.name.as_bytes())
        } else {
            panic!("Both `as_is` and `to_be` are `None`");
        }
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}
