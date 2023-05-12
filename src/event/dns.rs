use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
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
}

impl fmt::Display for DnsEventFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},DNS covert channel,3,{}",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto, self.query,
        )
    }
}

#[allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
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
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DnsCovertChannel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},DNS covert channel,{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.query,
            self.confidence
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
        EventCategory::CommandAndControl
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
        // TODO: implement
        0.0
    }
}
