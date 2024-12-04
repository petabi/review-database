use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{
    common::{AttrValue, Match},
    EventCategory, TriageScore, MEDIUM,
};
use crate::event::common::triage_scores_to_string;

macro_rules! dcerpc_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            DceRpcAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            DceRpcAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            DceRpcAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            DceRpcAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            DceRpcAttr::Proto => AttrValue::UInt($event.proto.into()),
            DceRpcAttr::Rtt => AttrValue::SInt($event.rtt),
            DceRpcAttr::NamedPipe => AttrValue::String(&$event.named_pipe),
            DceRpcAttr::Endpoint => AttrValue::String(&$event.endpoint),
            DceRpcAttr::Operation => AttrValue::String(&$event.operation),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum DceRpcAttr {
    #[strum(serialize = "dcerpc-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "dcerpc-id.orig_p")]
    SrcPort,
    #[strum(serialize = "dcerpc-id.resp_h")]
    DstAddr,
    #[strum(serialize = "dcerpc-id.resp_p")]
    DstPort,
    #[strum(serialize = "dcerpc-proto")]
    Proto,
    #[strum(serialize = "dcerpc-rtt")]
    Rtt,
    #[strum(serialize = "dcerpc-named_pipe")]
    NamedPipe,
    #[strum(serialize = "dcerpc-endpoint")]
    Endpoint,
    #[strum(serialize = "dcerpc-operation")]
    Operation,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListDceRpcFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub category: EventCategory,
}

impl fmt::Display for BlockListDceRpcFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation
        )
    }
}

pub struct BlockListDceRpc {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListDceRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation,
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListDceRpc {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListDceRpcFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            rtt: fields.rtt,
            named_pipe: fields.named_pipe,
            endpoint: fields.endpoint,
            operation: fields.operation,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<DceRpcAttr> for BlockListDceRpc {
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
        "block list dcerpc"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: DceRpcAttr) -> Option<AttrValue> {
        dcerpc_target_attr!(self, proto_attr)
    }
}
