use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! ssh_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
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
            SshAttr::HasshServerAlgorithms => AttrValue::String(&$event.hassh_server_algorithms),
            SshAttr::HasshServer => AttrValue::String(&$event.hassh_server),
            SshAttr::ClientShka => AttrValue::String(&$event.client_shka),
            SshAttr::ServerShka => AttrValue::String(&$event.server_shka),
        };
        Some(target_value)
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum SshAttr {
    #[strum(serialize = "ssh-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "ssh-id.orig_p")]
    SrcPort,
    #[strum(serialize = "ssh-id.resp_h")]
    DstAddr,
    #[strum(serialize = "ssh-id.resp_p")]
    DstPort,
    #[strum(serialize = "ssh-proto")]
    Proto,
    #[strum(serialize = "ssh-client")]
    Client,
    #[strum(serialize = "ssh-server")]
    Server,
    #[strum(serialize = "ssh-cipher_alg")]
    CipherAlg,
    #[strum(serialize = "ssh-mac_alg")]
    MacAlg,
    #[strum(serialize = "ssh-compression_alg")]
    CompressionAlg,
    #[strum(serialize = "ssh-kex_alg")]
    KexAlg,
    #[strum(serialize = "ssh-host_key_alg")]
    HostKeyAlg,
    #[strum(serialize = "ssh-hassh_algorithms")]
    HasshAlgorithms,
    #[strum(serialize = "ssh-hassh")]
    Hassh,
    #[strum(serialize = "ssh-hassh_server_algorithms")]
    HasshServerAlgorithms,
    #[strum(serialize = "ssh-hassh_server")]
    HasshServer,
    #[strum(serialize = "ssh-client_shka")]
    ClientShka,
    #[strum(serialize = "ssh-server_shka")]
    ServerShka,
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSshFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
}
impl fmt::Display for BlockListSshFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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
            self.server_shka
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListSsh {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListSsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListSsh {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListSshFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<SshAttr> for BlockListSsh {
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
        "block list ssh"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: SshAttr) -> Option<AttrValue> {
        ssh_target_attr!(self, proto_attr)
    }
}
