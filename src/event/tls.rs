use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, vector_to_string};

#[derive(Serialize, Deserialize)]
pub struct BlockListTlsFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub category: EventCategory,
}
impl fmt::Display for BlockListTlsFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.server_name,
            self.alpn_protocol,
            self.ja3,
            self.version,
            vector_to_string(&self.client_cipher_suites),
            vector_to_string(&self.client_extensions),
            self.cipher.to_string(),
            vector_to_string(&self.extensions),
            self.ja3s,
            self.serial,
            self.subject_country,
            self.subject_org_name,
            self.subject_common_name,
            self.validity_not_before.to_string(),
            self.validity_not_after.to_string(),
            self.subject_alt_name,
            self.issuer_country,
            self.issuer_org_name,
            self.issuer_org_unit_name,
            self.issuer_common_name,
            self.last_alert.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListTls {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.server_name,
            self.alpn_protocol,
            self.ja3,
            self.version,
            vector_to_string(&self.client_cipher_suites),
            vector_to_string(&self.client_extensions),
            self.cipher.to_string(),
            vector_to_string(&self.extensions),
            self.ja3s,
            self.serial,
            self.subject_country,
            self.subject_org_name,
            self.subject_common_name,
            self.validity_not_before.to_string(),
            self.validity_not_after.to_string(),
            self.subject_alt_name,
            self.issuer_country,
            self.issuer_org_name,
            self.issuer_org_unit_name,
            self.issuer_common_name,
            self.last_alert.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListTls {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListTlsFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            server_name: fields.server_name,
            alpn_protocol: fields.alpn_protocol,
            ja3: fields.ja3,
            version: fields.version,
            client_cipher_suites: fields.client_cipher_suites,
            client_extensions: fields.client_extensions,
            cipher: fields.cipher,
            extensions: fields.extensions,
            ja3s: fields.ja3s,
            serial: fields.serial,
            subject_country: fields.subject_country,
            subject_org_name: fields.subject_org_name,
            subject_common_name: fields.subject_common_name,
            validity_not_before: fields.validity_not_before,
            validity_not_after: fields.validity_not_after,
            subject_alt_name: fields.subject_alt_name,
            issuer_country: fields.issuer_country,
            issuer_org_name: fields.issuer_org_name,
            issuer_org_unit_name: fields.issuer_org_unit_name,
            issuer_common_name: fields.issuer_common_name,
            last_alert: fields.last_alert,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListTls {
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
        "block list tls"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}

pub struct SuspiciousTlsTraffic {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for SuspiciousTlsTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
                f,
                "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} triage_scores={:?}",
                self.source,
                self.src_addr.to_string(),
                self.src_port.to_string(),
                self.dst_addr.to_string(),
                self.dst_port.to_string(),
                self.proto.to_string(),
                self.last_time.to_string(),
                self.server_name,
                self.alpn_protocol,
                self.ja3,
                self.version,
                vector_to_string(&self.client_cipher_suites),
                vector_to_string(&self.client_extensions),
                self.cipher.to_string(),
                vector_to_string(&self.extensions),
                self.ja3s,
                self.serial,
                self.subject_country,
                self.subject_org_name,
                self.subject_common_name,
                self.validity_not_before.to_string(),
                self.validity_not_after.to_string(),
                self.subject_alt_name,
                self.issuer_country,
                self.issuer_org_name,
                self.issuer_org_unit_name,
                self.issuer_common_name,
                self.last_alert.to_string(),
                triage_scores_to_string(&self.triage_scores)
            )
    }
}

impl SuspiciousTlsTraffic {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListTlsFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            server_name: fields.server_name,
            alpn_protocol: fields.alpn_protocol,
            ja3: fields.ja3,
            version: fields.version,
            client_cipher_suites: fields.client_cipher_suites,
            client_extensions: fields.client_extensions,
            cipher: fields.cipher,
            extensions: fields.extensions,
            ja3s: fields.ja3s,
            serial: fields.serial,
            subject_country: fields.subject_country,
            subject_org_name: fields.subject_org_name,
            subject_common_name: fields.subject_common_name,
            validity_not_before: fields.validity_not_before,
            validity_not_after: fields.validity_not_after,
            subject_alt_name: fields.subject_alt_name,
            issuer_country: fields.issuer_country,
            issuer_org_name: fields.issuer_org_name,
            issuer_org_unit_name: fields.issuer_org_unit_name,
            issuer_common_name: fields.issuer_common_name,
            last_alert: fields.last_alert,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for SuspiciousTlsTraffic {
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
        "suspicious tls traffic"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }
    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}
