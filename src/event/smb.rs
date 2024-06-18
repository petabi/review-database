use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use crate::event::common::triage_scores_to_string;

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
            triage_scores: None,
        }
    }
}

impl Match for BlockListSmb {
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
        EventCategory::InitialAccess
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

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}
