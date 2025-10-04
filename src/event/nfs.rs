use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, NfsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    types::EventCategoryV0_41,
};

macro_rules! find_nfs_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        match $raw_event_attr {
            RawEventAttrKind::Nfs(attr) => {
                let target_value = match attr {
                    NfsAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                    NfsAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                    NfsAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                    NfsAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                    NfsAttr::Proto => AttrValue::UInt($event.proto.into()),
                    NfsAttr::ReadFiles => AttrValue::VecString(&$event.read_files),
                    NfsAttr::WriteFiles => AttrValue::VecString(&$event.write_files),
                };
                Some(target_value)
            }
            RawEventAttrKind::Conn(attr) => match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr($event.src_addr)),
                ConnAttr::SrcPort => Some(AttrValue::UInt($event.src_port.into())),
                ConnAttr::DstAddr => Some(AttrValue::Addr($event.dst_addr)),
                ConnAttr::DstPort => Some(AttrValue::UInt($event.dst_port.into())),
                ConnAttr::Proto => Some(AttrValue::UInt($event.proto.into())),
                ConnAttr::Duration => Some(AttrValue::SInt($event.duration)),
                ConnAttr::OrigBytes => Some(AttrValue::UInt($event.orig_bytes)),
                ConnAttr::RespBytes => Some(AttrValue::UInt($event.resp_bytes)),
                ConnAttr::OrigPkts => Some(AttrValue::UInt($event.orig_pkts)),
                ConnAttr::RespPkts => Some(AttrValue::UInt($event.resp_pkts)),
                _ => None,
            },
            _ => None,
        }
    }};
}

pub type BlocklistNfsFields = BlocklistNfsFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct BlocklistNfsFieldsV0_43 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub orig_bytes: u64,
    pub resp_pkts: u64,
    pub resp_bytes: u64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistNfsFieldsV0_42> for BlocklistNfsFieldsV0_43 {
    fn from(value: BlocklistNfsFieldsV0_42) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time: DateTime::from_timestamp_nanos(value.end_time),
            end_time: DateTime::from_timestamp_nanos(value.end_time),
            duration: 0,
            orig_pkts: 0,
            orig_bytes: 0,
            resp_pkts: 0,
            resp_bytes: 0,
            read_files: value.read_files,
            write_files: value.write_files,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNfsFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistNfsFieldsV0_41> for BlocklistNfsFieldsV0_42 {
    fn from(value: BlocklistNfsFieldsV0_41) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            read_files: value.read_files,
            write_files: value.write_files,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNfsFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistNfsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} orig_bytes={:?} resp_pkts={:?} resp_bytes={:?} read_files={:?} write_files={:?} confidence={:?}",
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
            self.orig_pkts.to_string(),
            self.orig_bytes.to_string(),
            self.resp_pkts.to_string(),
            self.resp_bytes.to_string(),
            self.read_files.join(","),
            self.write_files.join(","),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistNfs {
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
    pub orig_pkts: u64,
    pub orig_bytes: u64,
    pub resp_pkts: u64,
    pub resp_bytes: u64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} orig_bytes={:?} resp_pkts={:?} resp_bytes={:?} read_files={:?} write_files={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.orig_bytes.to_string(),
            self.resp_pkts.to_string(),
            self.resp_bytes.to_string(),
            self.read_files.join(","),
            self.write_files.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistNfs {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistNfsFields) -> Self {
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
            orig_pkts: fields.orig_pkts,
            orig_bytes: fields.orig_bytes,
            resp_pkts: fields.resp_pkts,
            resp_bytes: fields.resp_bytes,
            read_files: fields.read_files,
            write_files: fields.write_files,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistNfs {
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
        "blocklist nfs"
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
        find_nfs_attr_by_kind!(self, raw_event_attr)
    }
}
