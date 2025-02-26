use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriagePolicy, TriageScore, common::Match};
use crate::event::common::triage_scores_to_string;

#[derive(Serialize, Deserialize)]
pub struct BlockListKerberosFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub category: EventCategory,
}

impl fmt::Display for BlockListKerberosFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(",")
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListKerberos {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListKerberos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlockListKerberos {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListKerberosFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            client_time: fields.client_time,
            server_time: fields.server_time,
            error_code: fields.error_code,
            client_realm: fields.client_realm,
            cname_type: fields.cname_type,
            client_name: fields.client_name,
            realm: fields.realm,
            sname_type: fields.sname_type,
            service_name: fields.service_name,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListKerberos {
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
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "block list kerberos"
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
