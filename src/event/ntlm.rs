use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! ntlm_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            NtlmAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            NtlmAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            NtlmAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            NtlmAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            NtlmAttr::Proto => AttrValue::UInt($event.proto.into()),
            NtlmAttr::Protocol => AttrValue::String(&$event.protocol),
            NtlmAttr::Username => AttrValue::String(&$event.username),
            NtlmAttr::Hostname => AttrValue::String(&$event.hostname),
            NtlmAttr::Domainname => AttrValue::String(&$event.domainname),
            NtlmAttr::Success => AttrValue::String(&$event.success),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum NtlmAttr {
    #[strum(serialize = "ntlm-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "ntlm-id.orig_p")]
    SrcPort,
    #[strum(serialize = "ntlm-id.resp_h")]
    DstAddr,
    #[strum(serialize = "ntlm-id.resp_p")]
    DstPort,
    #[strum(serialize = "ntlm-proto")]
    Proto,
    #[strum(serialize = "ntlm-protocol")]
    Protocol,
    #[strum(serialize = "ntlm-username")]
    Username,
    #[strum(serialize = "ntlm-hostname")]
    Hostname,
    #[strum(serialize = "ntlm-domainname")]
    Domainname,
    #[strum(serialize = "ntlm-success")]
    Success,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListNtlmFields {
    pub source: String,
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
impl fmt::Display for BlockListNtlmFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?}",
            self.source,
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
pub struct BlockListNtlm {
    pub time: DateTime<Utc>,
    pub source: String,
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
impl fmt::Display for BlockListNtlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} triage_scores={:?}",
            self.source,
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
            triage_scores_to_string(&self.triage_scores)
        )
    }
}
impl BlockListNtlm {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListNtlmFields) -> Self {
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
            username: fields.username,
            hostname: fields.hostname,
            domainname: fields.domainname,
            success: fields.success,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<NtlmAttr> for BlockListNtlm {
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
        "block list ntlm"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: NtlmAttr) -> Option<AttrValue> {
        ntlm_target_attr!(self, proto_attr)
    }
}
