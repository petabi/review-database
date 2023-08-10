use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use crate::event::BLOCK_LIST;
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Serialize, Deserialize)]
pub struct BlockListKerberosFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub request_type: String,
    pub client: String,
    pub service: String,
    pub success: String,
    pub error_msg: String,
    pub from: i64,
    pub till: i64,
    pub cipher: String,
    pub forwardable: String,
    pub renewable: String,
    pub client_cert_subject: String,
    pub server_cert_subject: String,
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
    pub request_type: String,
    pub client: String,
    pub service: String,
    pub success: String,
    pub error_msg: String,
    pub from: i64,
    pub till: i64,
    pub cipher: String,
    pub forwardable: String,
    pub renewable: String,
    pub client_cert_subject: String,
    pub server_cert_subject: String,
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
            request_type: fields.request_type,
            client: fields.client,
            service: fields.service,
            success: fields.success,
            error_msg: fields.error_msg,
            from: fields.from,
            till: fields.till,
            cipher: fields.cipher,
            forwardable: fields.forwardable,
            renewable: fields.renewable,
            client_cert_subject: fields.client_cert_subject,
            server_cert_subject: fields.server_cert_subject,
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
