use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriagePolicy, TriageScore, common::Match};
use crate::event::common::{to_hardware_address, triage_scores_to_string};

#[derive(Serialize, Deserialize)]
pub struct BlocklistBootpFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
    pub category: EventCategory,
}
impl fmt::Display for BlocklistBootpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.op.to_string(),
            self.htype.to_string(),
            self.hops.to_string(),
            self.xid.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            to_hardware_address(&self.chaddr),
            self.sname.to_string(),
            self.file.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistBootp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistBootp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.op.to_string(),
            self.htype.to_string(),
            self.hops.to_string(),
            self.xid.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            to_hardware_address(&self.chaddr),
            self.sname.to_string(),
            self.file.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistBootp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistBootpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            op: fields.op,
            htype: fields.htype,
            hops: fields.hops,
            xid: fields.xid,
            ciaddr: fields.ciaddr,
            yiaddr: fields.yiaddr,
            siaddr: fields.siaddr,
            giaddr: fields.giaddr,
            chaddr: fields.chaddr,
            sname: fields.sname,
            file: fields.file,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistBootp {
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

    fn kind(&self) -> &'static str {
        "block list bootp"
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

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}
