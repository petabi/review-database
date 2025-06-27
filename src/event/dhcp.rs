use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{DhcpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    EventCategory, LearningMethod, MEDIUM, TriageScore,
    common::{AttrValue, Match},
};
use crate::event::common::{to_hardware_address, triage_scores_to_string, vector_to_string};

macro_rules! find_dhcp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Dhcp(attr) = $raw_event_attr {
            let target_value = match attr {
                DhcpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                DhcpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                DhcpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                DhcpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                DhcpAttr::Proto => AttrValue::UInt($event.proto.into()),
                DhcpAttr::MgsType => todo!(),
                DhcpAttr::CiAddr => AttrValue::Addr($event.ciaddr),
                DhcpAttr::YiAddr => AttrValue::Addr($event.yiaddr),
                DhcpAttr::SiAddr => AttrValue::Addr($event.siaddr),
                DhcpAttr::GiAddr => AttrValue::Addr($event.giaddr),
                DhcpAttr::SubNetMask => AttrValue::Addr($event.subnet_mask),
                DhcpAttr::Router => AttrValue::VecAddr(&$event.router),
                DhcpAttr::DomainNameServer => AttrValue::VecAddr(&$event.domain_name_server),
                DhcpAttr::ReqIpAddr => AttrValue::Addr($event.req_ip_addr),
                DhcpAttr::LeaseTime => AttrValue::UInt($event.lease_time.into()),
                DhcpAttr::ServerId => AttrValue::Addr($event.server_id),
                DhcpAttr::ParamReqList => AttrValue::VecUInt(
                    $event
                        .param_req_list
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                ),
                DhcpAttr::Message => AttrValue::String(&$event.message),
                DhcpAttr::RenewalTime => AttrValue::UInt($event.renewal_time.into()),
                DhcpAttr::RebindingTime => AttrValue::UInt($event.rebinding_time.into()),
                DhcpAttr::ClassId => AttrValue::VecRaw(&$event.class_id),
                DhcpAttr::ClientIdType => AttrValue::UInt($event.client_id_type.into()),
                DhcpAttr::ClientId => AttrValue::VecRaw(&$event.client_id),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistDhcpFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub confidence: f32,
    pub category: EventCategory,
}

// TODO: DHCP client identifier type.
//  - 00: Ascii string (need to support)
//  - 01: MAC address
//  - XX: Hexdecimal number

impl BlocklistDhcpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.msg_type.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            self.subnet_mask.to_string(),
            vector_to_string(&self.router),
            vector_to_string(&self.domain_name_server),
            self.req_ip_addr.to_string(),
            self.lease_time.to_string(),
            self.server_id.to_string(),
            vector_to_string(&self.param_req_list),
            self.message,
            self.renewal_time.to_string(),
            self.rebinding_time.to_string(),
            std::str::from_utf8(&self.class_id)
                .unwrap_or_default()
                .to_string(),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistDhcp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistDhcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.msg_type.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            self.subnet_mask.to_string(),
            vector_to_string(&self.router),
            vector_to_string(&self.domain_name_server),
            self.req_ip_addr.to_string(),
            self.lease_time.to_string(),
            self.server_id.to_string(),
            vector_to_string(&self.param_req_list),
            self.message.to_string(),
            self.renewal_time.to_string(),
            self.rebinding_time.to_string(),
            std::str::from_utf8(&self.class_id)
                .unwrap_or_default()
                .to_string(),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistDhcp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDhcpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            msg_type: fields.msg_type,
            ciaddr: fields.ciaddr,
            yiaddr: fields.yiaddr,
            siaddr: fields.siaddr,
            giaddr: fields.giaddr,
            subnet_mask: fields.subnet_mask,
            router: fields.router,
            domain_name_server: fields.domain_name_server,
            req_ip_addr: fields.req_ip_addr,
            lease_time: fields.lease_time,
            server_id: fields.server_id,
            param_req_list: fields.param_req_list,
            message: fields.message,
            renewal_time: fields.renewal_time,
            rebinding_time: fields.rebinding_time,
            class_id: fields.class_id,
            client_id_type: fields.client_id_type,
            client_id: fields.client_id,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDhcp {
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
        "blocklist dhcp"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        find_dhcp_attr_by_kind!(self, raw_event_attr)
    }
}
