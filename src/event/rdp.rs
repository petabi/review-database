#![allow(clippy::module_name_repetitions)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{
    common::{vector_to_string, Match},
    EventCategory, TriageScore, MEDIUM,
};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! rdp_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            RdpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            RdpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            RdpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            RdpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            RdpAttr::Proto => AttrValue::UInt($event.proto.into()),
            RdpAttr::Cookie => AttrValue::String(&$event.cookie),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum RdpAttr {
    #[strum(serialize = "rdp-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "rdp-id.orig_p")]
    SrcPort,
    #[strum(serialize = "rdp-id.resp_h")]
    DstAddr,
    #[strum(serialize = "rdp-id.resp_p")]
    DstPort,
    #[strum(serialize = "rdp-proto")]
    Proto,
    #[strum(serialize = "rdp-cookie")]
    Cookie,
}

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForceFields {
    pub src_addr: IpAddr,
    pub dst_addrs: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
    pub category: EventCategory,
}

impl fmt::Display for RdpBruteForceFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addrs={:?} start_time={:?} last_time={:?} proto={:?}",
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            self.proto.to_string()
        )
    }
}

pub struct RdpBruteForce {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addrs: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RdpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addrs={:?} start_time={:?} last_time={:?} proto={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            self.proto.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl RdpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &RdpBruteForceFields) -> Self {
        RdpBruteForce {
            time,
            src_addr: fields.src_addr,
            dst_addrs: fields.dst_addrs.clone(),
            start_time: fields.start_time,
            last_time: fields.last_time,
            proto: fields.proto,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<RdpAttr> for RdpBruteForce {
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
        0
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
        "rdp brute force"
    }

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: RdpAttr) -> Option<AttrValue> {
        match proto_attr {
            RdpAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
            RdpAttr::DstAddr => Some(AttrValue::VecAddr(&self.dst_addrs)),
            RdpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListRdpFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub cookie: String,
    pub category: EventCategory,
}

impl fmt::Display for BlockListRdpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} cookie={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.cookie
        )
    }
}
pub struct BlockListRdp {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub cookie: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListRdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} cookie={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.cookie,
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListRdp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListRdpFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            cookie: fields.cookie,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<RdpAttr> for BlockListRdp {
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

    fn kind(&self) -> &str {
        "block list rdp"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: RdpAttr) -> Option<AttrValue> {
        rdp_target_attr!(self, proto_attr)
    }
}
