#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{serde::ts_nanoseconds, DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, HIGH, MEDIUM};
use crate::event::common::{triage_scores_to_string, vector_to_string};

#[derive(Deserialize, Serialize)]
pub struct DnsEventFields {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
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

impl fmt::Display for DnsEventFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} session_end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?}",
            self.source,
            self.session_end_time.to_rfc3339(),
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

pub struct DnsCovertChannel {
    pub time: DateTime<Utc>,
    pub source: String,
    pub session_end_time: DateTime<Utc>,
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
            "source={:?} session_end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
            self.source,
            self.session_end_time.to_rfc3339(),
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
            source: fields.source,
            session_end_time: fields.session_end_time,
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
        "dns covert channel"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}

// TODO: Locky ransomware event uses same sruct with DnsCovertChannel. It can be merged.
pub struct LockyRansomware {
    pub time: DateTime<Utc>,
    pub source: String,
    pub session_end_time: DateTime<Utc>,
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
            "source={:?} session_end_time={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
            self.source,
            self.session_end_time.to_rfc3339(),
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
            source: fields.source,
            session_end_time: fields.session_end_time,
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
        HIGH
    }

    fn kind(&self) -> &str {
        "locky ransomware"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        0.0
    }
}

#[derive(Deserialize, Serialize)]
pub struct CryptocurrencyMiningPoolFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
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

impl fmt::Display for CryptocurrencyMiningPoolFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} session_end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.session_end_time.to_rfc3339(),
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
        )
    }
}

pub struct CryptocurrencyMiningPool {
    pub time: DateTime<Utc>,
    pub source: String,
    pub session_end_time: DateTime<Utc>,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for CryptocurrencyMiningPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} session_end_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.session_end_time.to_rfc3339(),
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
            source: fields.source,
            session_end_time: fields.session_end_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for CryptocurrencyMiningPool {
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
        "cryptocurrency mining pool"
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

#[derive(Deserialize, Serialize)]
pub struct BlockListDnsFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
}

impl fmt::Display for BlockListDnsFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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
        )
    }
}

pub struct BlockListDns {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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

impl BlockListDns {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListDnsFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListDns {
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
        "block list dns"
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
