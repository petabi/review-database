use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! nfs_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            NfsAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            NfsAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            NfsAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            NfsAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            NfsAttr::Proto => AttrValue::UInt($event.proto.into()),
            NfsAttr::ReadFiles => AttrValue::VecString(&$event.read_files),
            NfsAttr::WriteFiles => AttrValue::VecString(&$event.write_files),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum NfsAttr {
    #[strum(serialize = "nfs-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "nfs-id.orig_p")]
    SrcPort,
    #[strum(serialize = "nfs-id.resp_h")]
    DstAddr,
    #[strum(serialize = "nfs-id.resp_p")]
    DstPort,
    #[strum(serialize = "nfs-proto")]
    Proto,
    #[strum(serialize = "nfs-read_files")]
    ReadFiles,
    #[strum(serialize = "nfs-write_files")]
    WriteFiles,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListNfsFields {
    pub source: String,
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
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} read_files={:?} write_files={:?}",
            self.source,
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
    pub source: String,
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
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} read_files={:?} write_files={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.read_files.join(","),
            self.write_files.join(","),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListNfs {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListNfsFields) -> Self {
        Self {
            time,
            source: fields.source,
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

impl Match<NfsAttr> for BlockListNfs {
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
        "block list nfs"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: NfsAttr) -> Option<AttrValue> {
        nfs_target_attr!(self, proto_attr)
    }
}
