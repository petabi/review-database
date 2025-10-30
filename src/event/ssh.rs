use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, RawEventAttrKind, SshAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    types::EventCategoryV0_41,
};

macro_rules! find_ssh_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        match $raw_event_attr {
            RawEventAttrKind::Ssh(attr) => {
                let target_value = match attr {
                    SshAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                    SshAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                    SshAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                    SshAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                    SshAttr::Proto => AttrValue::UInt($event.proto.into()),
                    SshAttr::Client => AttrValue::String(&$event.client),
                    SshAttr::Server => AttrValue::String(&$event.server),
                    SshAttr::CipherAlg => AttrValue::String(&$event.cipher_alg),
                    SshAttr::MacAlg => AttrValue::String(&$event.mac_alg),
                    SshAttr::CompressionAlg => AttrValue::String(&$event.compression_alg),
                    SshAttr::KexAlg => AttrValue::String(&$event.kex_alg),
                    SshAttr::HostKeyAlg => AttrValue::String(&$event.host_key_alg),
                    SshAttr::HasshAlgorithms => AttrValue::String(&$event.hassh_algorithms),
                    SshAttr::Hassh => AttrValue::String(&$event.hassh),
                    SshAttr::HasshServerAlgorithms => {
                        AttrValue::String(&$event.hassh_server_algorithms)
                    }
                    SshAttr::HasshServer => AttrValue::String(&$event.hassh_server),
                    SshAttr::ClientShka => AttrValue::String(&$event.client_shka),
                    SshAttr::ServerShka => AttrValue::String(&$event.server_shka),
                };
                Some(target_value)
            }
            RawEventAttrKind::Conn(attr) => match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr($event.src_addr)),
                ConnAttr::SrcPort => Some(AttrValue::UInt($event.src_port.into())),
                ConnAttr::DstAddr => Some(AttrValue::Addr($event.dst_addr)),
                ConnAttr::DstPort => Some(AttrValue::UInt($event.dst_port.into())),
                ConnAttr::Proto => Some(AttrValue::UInt($event.proto.into())),
                ConnAttr::Duration => Some(AttrValue::SInt($event.duration)),
                ConnAttr::OrigBytes => Some(AttrValue::UInt($event.orig_bytes)),
                ConnAttr::RespBytes => Some(AttrValue::UInt($event.resp_bytes)),
                ConnAttr::OrigPkts => Some(AttrValue::UInt($event.orig_pkts)),
                ConnAttr::RespPkts => Some(AttrValue::UInt($event.resp_pkts)),
                _ => None,
            },
            _ => None,
        }
    }};
}

pub type BlocklistSshFields = BlocklistSshFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct BlocklistSshFieldsV0_43 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub orig_bytes: u64,
    pub resp_pkts: u64,
    pub resp_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistSshFieldsV0_42> for BlocklistSshFieldsV0_43 {
    fn from(value: BlocklistSshFieldsV0_42) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time: DateTime::from_timestamp_nanos(value.end_time),
            end_time: DateTime::from_timestamp_nanos(value.end_time),
            duration: 0,
            orig_pkts: 0,
            orig_bytes: 0,
            resp_pkts: 0,
            resp_bytes: 0,
            client: value.client,
            server: value.server,
            cipher_alg: value.cipher_alg,
            mac_alg: value.mac_alg,
            compression_alg: value.compression_alg,
            kex_alg: value.kex_alg,
            host_key_alg: value.host_key_alg,
            hassh_algorithms: value.hassh_algorithms,
            hassh: value.hassh,
            hassh_server_algorithms: value.hassh_server_algorithms,
            hassh_server: value.hassh_server,
            client_shka: value.client_shka,
            server_shka: value.server_shka,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSshFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistSshFieldsV0_41> for BlocklistSshFieldsV0_42 {
    fn from(value: BlocklistSshFieldsV0_41) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            client: value.client,
            server: value.server,
            cipher_alg: value.cipher_alg,
            mac_alg: value.mac_alg,
            compression_alg: value.compression_alg,
            kex_alg: value.kex_alg,
            host_key_alg: value.host_key_alg,
            hassh_algorithms: value.hassh_algorithms,
            hassh: value.hassh,
            hassh_server_algorithms: value.hassh_server_algorithms,
            hassh_server: value.hassh_server,
            client_shka: value.client_shka,
            server_shka: value.server_shka,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSshFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistSshFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} orig_bytes={:?} resp_pkts={:?} resp_bytes={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?} confidence={:?}",
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
            self.orig_pkts.to_string(),
            self.orig_bytes.to_string(),
            self.resp_pkts.to_string(),
            self.resp_bytes.to_string(),
            self.client,
            self.server,
            self.cipher_alg,
            self.mac_alg,
            self.compression_alg,
            self.kex_alg,
            self.host_key_alg,
            self.hassh_algorithms,
            self.hassh,
            self.hassh_server_algorithms,
            self.hassh_server,
            self.client_shka,
            self.server_shka,
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistSsh {
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
    pub orig_pkts: u64,
    pub orig_bytes: u64,
    pub resp_pkts: u64,
    pub resp_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistSsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} orig_bytes={:?} resp_pkts={:?} resp_bytes={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.orig_bytes.to_string(),
            self.resp_pkts.to_string(),
            self.resp_bytes.to_string(),
            self.client,
            self.server,
            self.cipher_alg,
            self.mac_alg,
            self.compression_alg,
            self.kex_alg,
            self.host_key_alg,
            self.hassh_algorithms,
            self.hassh,
            self.hassh_server_algorithms,
            self.hassh_server,
            self.client_shka,
            self.server_shka,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistSsh {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistSshFields) -> Self {
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
            orig_pkts: fields.orig_pkts,
            orig_bytes: fields.orig_bytes,
            resp_pkts: fields.resp_pkts,
            resp_bytes: fields.resp_bytes,
            client: fields.client,
            server: fields.server,
            cipher_alg: fields.cipher_alg,
            mac_alg: fields.mac_alg,
            compression_alg: fields.compression_alg,
            kex_alg: fields.kex_alg,
            host_key_alg: fields.host_key_alg,
            hassh_algorithms: fields.hassh_algorithms,
            hassh: fields.hassh,
            hassh_server_algorithms: fields.hassh_server_algorithms,
            hassh_server: fields.hassh_server,
            client_shka: fields.client_shka,
            server_shka: fields.server_shka,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistSsh {
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
        "blocklist ssh"
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
        find_ssh_attr_by_kind!(self, raw_event_attr)
    }
}
