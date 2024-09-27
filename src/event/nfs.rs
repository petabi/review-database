use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{NfsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! nfs_target_attr {
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
pub struct BlockListNfsFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub category: EventCategory,
}
impl fmt::Display for BlockListNfsFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} read_files={:?} write_files={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.read_files.join(","),
            self.write_files.join(",")
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListNfs {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListNfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} read_files={:?} write_files={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.read_files.join(","),
            self.write_files.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlockListNfs {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListNfsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            read_files: fields.read_files,
            write_files: fields.write_files,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListNfs {
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
        "block list nfs"
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

    fn to_attr_value(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        nfs_target_attr!(self, raw_event_attr)
    }
}
