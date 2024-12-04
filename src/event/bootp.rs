use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{to_hardware_address, triage_scores_to_string, AttrValue};

macro_rules! bootp_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
            BootpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
            BootpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
            BootpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
            BootpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
            BootpAttr::Proto => AttrValue::UInt($event.proto.into()),
            BootpAttr::Op => AttrValue::UInt($event.op.into()),
            BootpAttr::Htype => AttrValue::UInt($event.htype.into()),
            BootpAttr::Hops => AttrValue::UInt($event.hops.into()),
            BootpAttr::Xid => AttrValue::UInt($event.xid.into()),
            BootpAttr::CiAddr => AttrValue::Addr($event.ciaddr),
            BootpAttr::YiAddr => AttrValue::Addr($event.yiaddr),
            BootpAttr::SiAddr => AttrValue::Addr($event.siaddr),
            BootpAttr::GiAddr => AttrValue::Addr($event.giaddr),
            BootpAttr::ChAddr => AttrValue::String(&$event.chaddr),
            BootpAttr::SName => AttrValue::String(&$event.sname),
            BootpAttr::File => AttrValue::String(&$event.file),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum BootpAttr {
    #[strum(serialize = "bootp-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "bootp-id.orig_p")]
    SrcPort,
    #[strum(serialize = "bootp-id.resp_h")]
    DstAddr,
    #[strum(serialize = "bootp-id.resp_p")]
    DstPort,
    #[strum(serialize = "bootp-proto")]
    Proto,
    #[strum(serialize = "bootp-op")]
    Op,
    #[strum(serialize = "bootp-htype")]
    Htype,
    #[strum(serialize = "bootp-hops")]
    Hops,
    #[strum(serialize = "bootp-xid")]
    Xid,
    #[strum(serialize = "bootp-ciaddr")]
    CiAddr,
    #[strum(serialize = "bootp-yiaddr")]
    YiAddr,
    #[strum(serialize = "bootp-siaddr")]
    SiAddr,
    #[strum(serialize = "bootp-giaddr")]
    GiAddr,
    #[strum(serialize = "bootp-chaddr")]
    ChAddr,
    #[strum(serialize = "bootp-sname")]
    SName,
    #[strum(serialize = "bootp-file")]
    File,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListBootpFields {
    pub source: String,
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
impl fmt::Display for BlockListBootpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?}",
            self.source,
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
pub struct BlockListBootp {
    pub time: DateTime<Utc>,
    pub source: String,
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
    pub chaddr: String,
    pub sname: String,
    pub file: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListBootp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?} triage_scores={:?}",
            self.source,
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
            self.chaddr,
            self.sname.to_string(),
            self.file.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListBootp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListBootpFields) -> Self {
        Self {
            time,
            source: fields.source,
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
            chaddr: to_hardware_address(&fields.chaddr),
            sname: fields.sname,
            file: fields.file,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<BootpAttr> for BlockListBootp {
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
        "block list bootp"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: BootpAttr) -> Option<AttrValue> {
        bootp_target_attr!(self, proto_attr)
    }
}
