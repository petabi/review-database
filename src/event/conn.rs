use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, vector_to_string};

#[derive(Serialize, Deserialize)]
pub struct PortScanFields {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
}

impl fmt::Display for PortScanFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_ports={:?} start_time={:?} last_time={:?} proto={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            vector_to_string(&self.dst_ports),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            self.proto.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct PortScan {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_ports={:?} start_time={:?} last_time={:?} proto={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            vector_to_string(&self.dst_ports),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            self.proto.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl PortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &PortScanFields) -> Self {
        PortScan {
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_ports: fields.dst_ports.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for PortScan {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Reconnaissance
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "port scan"
    }

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFields {
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl fmt::Display for MultiHostPortScanFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addrs={:?} dst_port={:?} proto={:?} start_time={:?} last_time={:?}",
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct MultiHostPortScan {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for MultiHostPortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addrs={:?} dst_port={:?} proto={:?} start_time={:?} last_time={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl MultiHostPortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &MultiHostPortScanFields) -> Self {
        MultiHostPortScan {
            time,
            src_addr: fields.src_addr,
            dst_port: fields.dst_port,
            dst_addrs: fields.dst_addrs.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for MultiHostPortScan {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Reconnaissance
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "multi host port scan"
    }

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExternalDdosFields {
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl fmt::Display for ExternalDdosFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addrs={:?} dst_addr={:?} proto={:?} start_time={:?} last_time={:?}",
            vector_to_string(&self.src_addrs),
            self.dst_addr.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct ExternalDdos {
    pub time: DateTime<Utc>,
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for ExternalDdos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addrs={:?} dst_addr={:?} proto={:?} start_time={:?} last_time={:?} triage_scores={:?}",
            vector_to_string(&self.src_addrs),
            self.dst_addr.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl ExternalDdos {
    pub(super) fn new(time: DateTime<Utc>, fields: &ExternalDdosFields) -> Self {
        ExternalDdos {
            time,
            src_addrs: fields.src_addrs.clone(),
            dst_addr: fields.dst_addr,
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for ExternalDdos {
    fn src_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Impact
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "external ddos"
    }

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListConnFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl fmt::Display for BlockListConnFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} conn_state={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            self.duration.to_string(),
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListConn {
    pub source: String,
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} conn_state={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            self.duration.to_string(),
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListConn {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListConnFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            conn_state: fields.conn_state,
            duration: fields.duration,
            service: fields.service,
            orig_bytes: fields.orig_bytes,
            resp_bytes: fields.resp_bytes,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            triage_scores: None,
        }
    }
}

impl Match for BlockListConn {
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
        "block list conn"
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
