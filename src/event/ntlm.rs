use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriagePolicy, TriageScore, common::Match};
use crate::event::common::triage_scores_to_string;

#[derive(Serialize, Deserialize)]
pub struct BlocklistNtlmFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub category: EventCategory,
}
impl fmt::Display for BlocklistNtlmFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.protocol,
            self.username,
            self.hostname,
            self.domainname,
            self.success
        )
    }
}
#[allow(clippy::module_name_repetitions)]
pub struct BlocklistNtlm {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNtlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.protocol,
            self.username,
            self.hostname,
            self.domainname,
            self.success,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}
impl BlocklistNtlm {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistNtlmFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            protocol: fields.protocol,
            username: fields.username,
            hostname: fields.hostname,
            domainname: fields.domainname,
            success: fields.success,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistNtlm {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "block list ntlm"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}
