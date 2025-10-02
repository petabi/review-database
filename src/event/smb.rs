use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, RawEventAttrKind, SmbAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    types::EventCategoryV0_41,
};

pub type BlocklistSmbFields = BlocklistSmbFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct BlocklistSmbFieldsV0_43 {
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
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSmbFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistSmbFieldsV0_41> for BlocklistSmbFieldsV0_42 {
    fn from(value: BlocklistSmbFieldsV0_41) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            command: value.command,
            path: value.path,
            service: value.service,
            file_name: value.file_name,
            file_size: value.file_size,
            resource_type: value.resource_type,
            fid: value.fid,
            create_time: value.create_time,
            access_time: value.access_time,
            write_time: value.write_time,
            change_time: value.change_time,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

impl From<BlocklistSmbFieldsV0_42> for BlocklistSmbFieldsV0_43 {
    fn from(value: BlocklistSmbFieldsV0_42) -> Self {
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
            command: value.command,
            path: value.path,
            service: value.service,
            file_name: value.file_name,
            file_size: value.file_size,
            resource_type: value.resource_type,
            fid: value.fid,
            create_time: value.create_time,
            access_time: value.access_time,
            write_time: value.write_time,
            change_time: value.change_time,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSmbFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistSmbFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} command={:?} path={:?} service={:?} file_name={:?} file_size={:?} resource_type={:?} fid={:?} create_time={:?} access_time={:?} write_time={:?} change_time={:?} confidence={:?}",
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
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistSmb {
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
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistSmb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} command={:?} path={:?} service={:?} file_name={:?} file_size={:?} resource_type={:?} fid={:?} create_time={:?} access_time={:?} write_time={:?} change_time={:?} triage_scores={:?}",
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
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}
impl BlocklistSmb {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistSmbFields) -> Self {
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
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistSmb {
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
        "blocklist smb"
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
            RawEventAttrKind::Smb(attr) => match attr {
                SmbAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                SmbAttr::SrcPort => Some(AttrValue::UInt(self.src_port.into())),
                SmbAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                SmbAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                SmbAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                SmbAttr::Command => Some(AttrValue::UInt(self.command.into())),
                SmbAttr::Path => Some(AttrValue::String(&self.path)),
                SmbAttr::Service => Some(AttrValue::String(&self.service)),
                SmbAttr::FileName => Some(AttrValue::String(&self.file_name)),
                SmbAttr::FileSize => Some(AttrValue::UInt(self.file_size)),
                SmbAttr::ResourceType => Some(AttrValue::UInt(self.resource_type.into())),
                SmbAttr::Fid => Some(AttrValue::UInt(self.fid.into())),
                SmbAttr::CreateTime => Some(AttrValue::SInt(self.create_time)),
                SmbAttr::AccessTime => Some(AttrValue::SInt(self.access_time)),
                SmbAttr::WriteTime => Some(AttrValue::SInt(self.write_time)),
                SmbAttr::ChangeTime => Some(AttrValue::SInt(self.change_time)),
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
