#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{DnsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, HIGH, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string, vector_to_string};

macro_rules! find_dns_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Dns(attr) = $raw_event_attr {
            let target_value = match attr {
                DnsAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                DnsAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                DnsAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                DnsAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                DnsAttr::Proto => AttrValue::UInt($event.proto.into()),
                DnsAttr::Query => AttrValue::String(&$event.query),
                DnsAttr::Answer => AttrValue::VecString(&$event.answer),
                DnsAttr::TransId => AttrValue::UInt($event.trans_id.into()),
                DnsAttr::Rtt => AttrValue::SInt($event.rtt.into()),
                DnsAttr::QClass => AttrValue::UInt($event.qclass.into()),
                DnsAttr::QType => AttrValue::UInt($event.qtype.into()),
                DnsAttr::RCode => AttrValue::UInt($event.rcode.into()),
                DnsAttr::AA => AttrValue::Bool($event.aa_flag),
                DnsAttr::TC => AttrValue::Bool($event.tc_flag),
                DnsAttr::RD => AttrValue::Bool($event.rd_flag),
                DnsAttr::RA => AttrValue::Bool($event.ra_flag),
                DnsAttr::Ttl => {
                    AttrValue::VecSInt($event.ttl.iter().map(|val| i64::from(*val)).collect())
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Deserialize, Serialize)]
pub struct DnsEventFields {
    pub sensor: String,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl DnsEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.end_time.to_rfc3339(),
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct DnsCovertChannel {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DnsCovertChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.end_time.to_rfc3339(),
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl DnsCovertChannel {
    pub(super) fn new(time: DateTime<Utc>, fields: DnsEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            end_time: fields.end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for DnsCovertChannel {
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
        "dns covert channel"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }
}

// TODO: Locky ransomware event uses same sruct with DnsCovertChannel. It can be merged.
pub struct LockyRansomware {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LockyRansomware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.end_time.to_rfc3339(),
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl LockyRansomware {
    pub(super) fn new(time: DateTime<Utc>, fields: DnsEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            end_time: fields.end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LockyRansomware {
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
        HIGH
    }

    fn kind(&self) -> &'static str {
        "locky ransomware"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }
}

pub type CryptocurrencyMiningPoolFields = CryptocurrencyMiningPoolFieldsV0_41;

impl CryptocurrencyMiningPoolFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.coins.join(","),
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct CryptocurrencyMiningPoolFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<CryptocurrencyMiningPoolFieldsV0_39> for CryptocurrencyMiningPoolFieldsV0_41 {
    fn from(value: CryptocurrencyMiningPoolFieldsV0_39) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            query: value.query,
            answer: value.answer,
            trans_id: value.trans_id,
            rtt: value.rtt,
            qclass: value.qclass,
            qtype: value.qtype,
            rcode: value.rcode,
            aa_flag: value.aa_flag,
            tc_flag: value.tc_flag,
            rd_flag: value.rd_flag,
            ra_flag: value.ra_flag,
            ttl: value.ttl,
            coins: value.coins,
            confidence: 1.0, // default value for CryptocurrencyMiningPool
            category: value.category,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct CryptocurrencyMiningPoolFieldsV0_39 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub category: EventCategory,
}

#[derive(Serialize, Deserialize)]
pub struct CryptocurrencyMiningPool {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for CryptocurrencyMiningPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.coins.join(","),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl CryptocurrencyMiningPool {
    pub(super) fn new(time: DateTime<Utc>, fields: CryptocurrencyMiningPoolFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            end_time: fields.end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            coins: fields.coins,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for CryptocurrencyMiningPool {
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
        "cryptocurrency mining pool"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_dns_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistDnsFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl BlocklistDnsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
        )
    }
}

pub struct BlocklistDns {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistDns {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDnsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDns {
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
        "blocklist dns"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }
}
