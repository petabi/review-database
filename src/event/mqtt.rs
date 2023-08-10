use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use crate::event::BLOCK_LIST;
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Serialize, Deserialize)]
pub struct BlockListMqttFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
}

impl fmt::Display for BlockListMqttFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},BlockListMqtt,3",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListMqtt {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListMqtt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},BlockListMqtt",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
        )
    }
}

impl BlockListMqtt {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListMqttFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            protocol: fields.protocol,
            version: fields.version,
            client_id: fields.client_id,
            connack_reason: fields.connack_reason,
            subscribe: fields.subscribe,
            suback_reason: fields.suback_reason,
            triage_scores: None,
        }
    }
}

impl Match for BlockListMqtt {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::InitialAccess
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        BLOCK_LIST
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}
