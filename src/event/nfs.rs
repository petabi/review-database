use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{NfsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_nfs_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Nfs(attr) = $raw_event_attr {
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
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistNfsFields {
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
    pub category: EventCategory,
}

impl BlocklistNfsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} read_files={:?} write_files={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
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
    pub end_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} read_files={:?} write_files={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
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
            end_time: fields.end_time,
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

    fn category(&self) -> EventCategory {
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
