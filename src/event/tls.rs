use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RawEventAttrKind, TlsAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string, vector_to_string};

macro_rules! find_tls_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Tls(attr) = $raw_event_attr {
            let target_value = match attr {
                TlsAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                TlsAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                TlsAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                TlsAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                TlsAttr::Proto => AttrValue::UInt($event.proto.into()),
                TlsAttr::ServerName => AttrValue::String(&$event.server_name),
                TlsAttr::AlpnProtocol => AttrValue::String(&$event.server_name),
                TlsAttr::Ja3 => AttrValue::String(&$event.ja3),
                TlsAttr::Version => AttrValue::String(&$event.version),
                TlsAttr::ClientCipherSuites => AttrValue::VecUInt(
                    $event
                        .client_cipher_suites
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                ),
                TlsAttr::ClientExtensions => AttrValue::VecUInt(
                    $event
                        .client_extensions
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                ),
                TlsAttr::Cipher => AttrValue::UInt($event.cipher.into()),
                TlsAttr::Extensions => AttrValue::VecUInt(
                    $event
                        .extensions
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                ),
                TlsAttr::Ja3s => AttrValue::String(&$event.ja3s),
                TlsAttr::Serial => AttrValue::String(&$event.serial),
                TlsAttr::SubjectCountry => AttrValue::String(&$event.subject_country),
                TlsAttr::SubjectOrgName => AttrValue::String(&$event.subject_org_name),
                TlsAttr::SubjectCommonName => AttrValue::String(&$event.subject_common_name),
                TlsAttr::ValidityNotBefore => AttrValue::SInt($event.validity_not_before.into()),
                TlsAttr::ValidityNotAfter => AttrValue::SInt($event.validity_not_after.into()),
                TlsAttr::SubjectAltName => AttrValue::String(&$event.subject_alt_name),
                TlsAttr::IssuerCountry => AttrValue::String(&$event.issuer_country),
                TlsAttr::IssuerOrgName => AttrValue::String(&$event.issuer_org_name),
                TlsAttr::IssuerOrgUnitName => AttrValue::String(&$event.issuer_org_unit_name),
                TlsAttr::IssuerCommonName => AttrValue::String(&$event.issuer_common_name),
                TlsAttr::LastAlert => AttrValue::UInt($event.last_alert.into()),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistTlsFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub confidence: f32,
    pub category: EventCategory,
}

impl BlocklistTlsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
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
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistTls {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
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
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistTls {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistTlsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
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
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistTls {
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
        "blocklist tls"
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
        find_tls_attr_by_kind!(self, raw_event_attr)
    }
}

pub struct SuspiciousTlsTraffic {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for SuspiciousTlsTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
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
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl SuspiciousTlsTraffic {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistTlsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
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
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for SuspiciousTlsTraffic {
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
        "suspicious tls traffic"
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
        find_tls_attr_by_kind!(self, raw_event_attr)
    }
}
