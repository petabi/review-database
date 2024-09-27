use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! smb_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            SmbAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            SmbAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            SmbAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            SmbAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            SmbAttr::Proto => AttrValue::UInt($event.proto.into()),
            SmbAttr::Command => AttrValue::UInt($event.command.into()),
            SmbAttr::Path => AttrValue::String(&$event.path),
            SmbAttr::Service => AttrValue::String(&$event.service),
            SmbAttr::FileName => AttrValue::String(&$event.file_name),
            SmbAttr::FileSize => AttrValue::UInt($event.file_size),
            SmbAttr::ResourceType => AttrValue::UInt($event.resource_type.into()),
            SmbAttr::Fid => AttrValue::UInt($event.fid.into()),
            SmbAttr::CreateTime => AttrValue::SInt($event.create_time),
            SmbAttr::AccessTime => AttrValue::SInt($event.access_time),
            SmbAttr::WriteTime => AttrValue::SInt($event.write_time),
            SmbAttr::ChangeTime => AttrValue::SInt($event.change_time),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum SmbAttr {
    #[strum(serialize = "smb-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "smb-id.orig_p")]
    SrcPort,
    #[strum(serialize = "smb-id.resp_h")]
    DstAddr,
    #[strum(serialize = "smb-id.resp_p")]
    DstPort,
    #[strum(serialize = "smb-proto")]
    Proto,
    #[strum(serialize = "smb-command")]
    Command,
    #[strum(serialize = "smb-path")]
    Path,
    #[strum(serialize = "smb-service")]
    Service,
    #[strum(serialize = "smb-file_name")]
    FileName,
    #[strum(serialize = "smb-file_size")]
    FileSize,
    #[strum(serialize = "smb-resource_type")]
    ResourceType,
    #[strum(serialize = "smb-fid")]
    Fid,
    #[strum(serialize = "smb-create_time")]
    CreateTime,
    #[strum(serialize = "smb-access_time")]
    AccessTime,
    #[strum(serialize = "smb-write_time")]
    WriteTime,
    #[strum(serialize = "smb-change_time")]
    ChangeTime,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSmbFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
    pub category: EventCategory,
}
impl fmt::Display for BlockListSmbFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} command={:?} path={:?} service={:?} file_name={:?} file_size={:?} resource_type={:?} fid={:?} create_time={:?} access_time={:?} write_time={:?} change_time={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.command.to_string(),
            self.path,
            self.service,
            self.file_name,
            self.file_size.to_string(),
            self.resource_type.to_string(),
            self.fid.to_string(),
            self.create_time.to_string(),
            self.access_time.to_string(),
            self.write_time.to_string(),
            self.change_time.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListSmb {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListSmb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} command={:?} path={:?} service={:?} file_name={:?} file_size={:?} resource_type={:?} fid={:?} create_time={:?} access_time={:?} write_time={:?} change_time={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.command.to_string(),
            self.path,
            self.service,
            self.file_name,
            self.file_size.to_string(),
            self.resource_type.to_string(),
            self.fid.to_string(),
            self.create_time.to_string(),
            self.access_time.to_string(),
            self.write_time.to_string(),
            self.change_time.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}
impl BlockListSmb {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListSmbFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            command: fields.command,
            path: fields.path,
            service: fields.service,
            file_name: fields.file_name,
            file_size: fields.file_size,
            resource_type: fields.resource_type,
            fid: fields.fid,
            create_time: fields.create_time,
            access_time: fields.access_time,
            write_time: fields.write_time,
            change_time: fields.change_time,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<SmbAttr> for BlockListSmb {
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
        "block list smb"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: SmbAttr) -> Option<AttrValue> {
        smb_target_attr!(self, proto_attr)
    }
}
