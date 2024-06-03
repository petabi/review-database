use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};

#[derive(Serialize, Deserialize)]
pub struct BlockListKerberosFields {
    pub source: String,
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
}

impl fmt::Display for BlockListKerberosFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},BlockListKerberos,3",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListKerberos {
    pub time: DateTime<Utc>,
    pub source: String,
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
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListKerberos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},BlockListKerberos",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
        )
    }
}

impl BlockListKerberos {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListKerberosFields) -> Self {
        Self {
            time,
            source: fields.source,
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
        EventCategory::InitialAccess
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        "block list kerberos"
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
