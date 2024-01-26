use bincode::Options;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

use crate::Indexable;

type PortNumber = u16;

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub struct Node {
    pub id: u32,
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
    pub creation_time: DateTime<Utc>,
    pub apply_target_id: Option<u32>,
    pub apply_in_progress: bool,
}

impl Indexable for Node {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
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
