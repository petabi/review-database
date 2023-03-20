use super::{common::Match, EventCategory, EventFilter, TriagePolicy, TriageScore, LOW, MEDIUM};
use aho_corasick::AhoCorasickBuilder;
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Deserialize)]
pub(super) struct RepeatedHttpSessionsFields {
    source: String,
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
}

impl fmt::Display for RepeatedHttpSessionsFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},Repeated HTTP Sessions,3",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto
        )
    }
}

pub struct RepeatedHttpSessions {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RepeatedHttpSessions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},Repeted HTTP Sessions",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto
        )
    }
}

impl RepeatedHttpSessions {
    pub(super) fn new(time: DateTime<Utc>, fields: &RepeatedHttpSessionsFields) -> Self {
        RepeatedHttpSessions {
            time,
            source: fields.source.clone(),
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            triage_scores: None,
        }
    }
}

impl Match for RepeatedHttpSessions {
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
        EventCategory::Exfiltration
    }

    fn level(&self) -> std::num::NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        "repeated http sessions"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct HttpThreatFields {
    pub event_id: u64,
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub host: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
}

// Syslog format: 5-tuple,attack-name,severity,content
impl fmt::Display for HttpThreatFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},2,{}",
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.attack_kind,
            self.content,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct HttpThreat {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub host: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for HttpThreat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let content = self.content.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},{},{},HttpThreat,{},{},{},{},{},{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.source,
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.host,
            content,
            self.db_name,
            self.rule_id,
            self.cluster_id,
            self.attack_kind,
            self.confidence
        )
    }
}

impl HttpThreat {
    pub(super) fn new(time: DateTime<Utc>, fields: HttpThreatFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            host: fields.host,
            content: fields.content,
            db_name: fields.db_name,
            rule_id: fields.rule_id,
            cluster_id: fields.cluster_id,
            attack_kind: fields.attack_kind,
            confidence: fields.confidence,
            triage_scores: None,
        }
    }
}

impl Match for HttpThreat {
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
        EventCategory::HttpThreat
    }

    fn level(&self) -> NonZeroU8 {
        LOW
    }

    fn kind(&self) -> &str {
        "all"
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        if let Some(kinds) = &filter.kinds {
            let patterns = self
                .attack_kind
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<String>>();
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(patterns);
            if kinds.iter().all(|kind| {
                let words = kind
                    .split_whitespace()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>();
                !words.iter().all(|w| ac.is_match(w))
            }) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DgaFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
}

#[derive(Deserialize, Serialize)]
pub struct DomainGenerationAlgorithm {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DomainGenerationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},{},DGA,{},{},{},{},{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.method,
            self.host,
            self.uri,
            self.referer,
            user_agent,
            self.status_code
        )
    }
}

impl DomainGenerationAlgorithm {
    pub(super) fn new(time: DateTime<Utc>, fields: DgaFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            duration: fields.duration,
            host: fields.host,
            method: fields.method,
            uri: fields.uri,
            referer: fields.referer,
            version: fields.version,
            user_agent: fields.user_agent,
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg,
            username: fields.username,
            password: fields.password,
            cookie: fields.cookie,
            content_encoding: fields.content_encoding,
            content_type: fields.content_type,
            cache_control: fields.cache_control,
            triage_scores: None,
        }
    }
}

impl Match for DomainGenerationAlgorithm {
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
        LOW
    }

    fn kind(&self) -> &str {
        "dga"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}
