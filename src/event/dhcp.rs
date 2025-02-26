use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriagePolicy, TriageScore, common::Match};
use crate::event::common::{to_hardware_address, triage_scores_to_string, vector_to_string};

#[derive(Serialize, Deserialize)]
pub struct BlockListDhcpFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
}

// TODO: DHCP client identifier type.
//  - 00: Ascii string (need to support)
//  - 01: MAC address
//  - XX: Hexdecimal number

impl fmt::Display for BlockListDhcpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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
            to_hardware_address(&self.class_id),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListDhcp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListDhcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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
            to_hardware_address(&self.class_id),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlockListDhcp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListDhcpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListDhcp {
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
        "block list dhcp"
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
