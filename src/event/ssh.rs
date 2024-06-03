use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};

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
}

impl fmt::Display for BlockListSshFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},BlockListSsh,3",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto,
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
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListSsh {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},BlockListSsh",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
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
            triage_scores: None,
        }
    }
}

impl Match for BlockListSsh {
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
        "block list ssh"
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
