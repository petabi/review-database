use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, NtlmAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    types::EventCategoryV0_41,
};

pub type BlocklistNtlmFields = BlocklistNtlmFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct BlocklistNtlmFieldsV0_43 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNtlmFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistNtlmFieldsV0_41> for BlocklistNtlmFieldsV0_42 {
    fn from(value: BlocklistNtlmFieldsV0_41) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            protocol: value.protocol,
            username: value.username,
            hostname: value.hostname,
            domainname: value.domainname,
            success: value.success,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

impl From<BlocklistNtlmFieldsV0_42> for BlocklistNtlmFieldsV0_43 {
    fn from(value: BlocklistNtlmFieldsV0_42) -> Self {
        let end_time = DateTime::from_timestamp_nanos(value.end_time);
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time: end_time,
            end_time,
            duration: 0,
            orig_bytes: 0,
            resp_bytes: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: value.protocol,
            username: value.username,
            hostname: value.hostname,
            domainname: value.domainname,
            success: value.success,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNtlmFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistNtlmFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.protocol,
            self.username,
            self.hostname,
            self.domainname,
            self.success,
            self.confidence.to_string(),
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
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNtlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
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
            start_time: fields.start_time,
            end_time: fields.end_time,
            duration: fields.duration,
            orig_bytes: fields.orig_bytes,
            resp_bytes: fields.resp_bytes,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            protocol: fields.protocol,
            username: fields.username,
            hostname: fields.hostname,
            domainname: fields.domainname,
            success: fields.success,
            confidence: fields.confidence,
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

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "blocklist ntlm"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        match raw_event_attr {
            RawEventAttrKind::Ntlm(attr) => match attr {
                NtlmAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                NtlmAttr::SrcPort => Some(AttrValue::UInt(self.src_port.into())),
                NtlmAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                NtlmAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                NtlmAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                NtlmAttr::Protocol => Some(AttrValue::String(&self.protocol)),
                NtlmAttr::Username => Some(AttrValue::String(&self.username)),
                NtlmAttr::Hostname => Some(AttrValue::String(&self.hostname)),
                NtlmAttr::Domainname => Some(AttrValue::String(&self.domainname)),
                NtlmAttr::Success => Some(AttrValue::String(&self.success)),
            },
            RawEventAttrKind::Conn(attr) => match attr {
                ConnAttr::Duration => Some(AttrValue::SInt(self.duration)),
                ConnAttr::OrigBytes => Some(AttrValue::UInt(self.orig_bytes)),
                ConnAttr::RespBytes => Some(AttrValue::UInt(self.resp_bytes)),
                ConnAttr::OrigPkts => Some(AttrValue::UInt(self.orig_pkts)),
                ConnAttr::RespPkts => Some(AttrValue::UInt(self.resp_pkts)),
                ConnAttr::OrigL2Bytes => Some(AttrValue::UInt(self.orig_l2_bytes)),
                ConnAttr::RespL2Bytes => Some(AttrValue::UInt(self.resp_l2_bytes)),
                _ => None,
            },
            _ => None,
        }
    }
}
