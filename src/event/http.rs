use std::{fmt, net::IpAddr, num::NonZeroU8};

use aho_corasick::AhoCorasickBuilder;
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};

use super::{common::Match, EventCategory, EventFilter, TriagePolicy, TriageScore, LOW, MEDIUM};

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
            "{},{},{},{},{},{},Repeated HTTP Sessions",
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

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatFields {
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
}

// Syslog format: 5-tuple,attack-name,severity,content
impl fmt::Display for HttpThreatFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},{},2,{},{},{},{},{},{}",
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.attack_kind,
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.status_code,
            user_agent
        )
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreat {
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for HttpThreat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = format!(
            "{} {} {} {} {} {}",
            self.method, self.host, self.uri, self.referer, self.status_code, self.user_agent
        );
        content = content.replace(',', " ");
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
            duration: fields.duration,
            method: fields.method,
            host: fields.host,
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
            orig_filenames: fields.orig_filenames,
            orig_mime_types: fields.orig_mime_types,
            resp_filenames: fields.resp_filenames,
            resp_mime_types: fields.resp_mime_types,
            post_body: fields.post_body,
            state: fields.state,
            db_name: fields.db_name,
            rule_id: fields.rule_id,
            matched_to: fields.matched_to,
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
        EventCategory::Reconnaissance
    }

    fn level(&self) -> NonZeroU8 {
        LOW
    }

    fn kind(&self) -> &str {
        "http threat"
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
}

impl fmt::Display for DgaFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},DGA,3,{},{},{},{},{},{}",
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.status_code,
            user_agent
        )
    }
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
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
            self.status_code,
            user_agent
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
            orig_filenames: fields.orig_filenames,
            orig_mime_types: fields.orig_mime_types,
            resp_filenames: fields.resp_filenames,
            resp_mime_types: fields.resp_mime_types,
            post_body: fields.post_body,
            state: fields.state,
            confidence: fields.confidence,
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

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct NonBrowserFields {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
}

impl fmt::Display for NonBrowserFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},Non Browser,3,{}",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto, user_agent
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct NonBrowser {
    pub time: DateTime<Utc>,
    pub source: String,
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for NonBrowser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},{},Non Browser,{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            user_agent
        )
    }
}

impl NonBrowser {
    pub(super) fn new(time: DateTime<Utc>, fields: &NonBrowserFields) -> Self {
        NonBrowser {
            time,
            source: fields.source.clone(),
            session_end_time: fields.session_end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referrer: fields.referrer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            orig_filenames: fields.orig_filenames.clone(),
            orig_mime_types: fields.orig_mime_types.clone(),
            resp_filenames: fields.resp_filenames.clone(),
            resp_mime_types: fields.resp_mime_types.clone(),
            post_body: fields.post_body.clone(),
            state: fields.state.clone(),
            triage_scores: None,
        }
    }
}

impl Match for NonBrowser {
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
        "non browser"
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

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockListHttpFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
}

impl fmt::Display for BlockListHttpFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},BlockListHttp,3,{}",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto, user_agent
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct BlockListHttp {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListHttp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_agent = self.user_agent.replace(',', " ");
        write!(
            f,
            "{},{},{},{},{},{},BlockListHttp,{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
            user_agent
        )
    }
}

impl BlockListHttp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListHttpFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referrer: fields.referrer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            orig_filenames: fields.orig_filenames.clone(),
            orig_mime_types: fields.orig_mime_types.clone(),
            resp_filenames: fields.resp_filenames.clone(),
            resp_mime_types: fields.resp_mime_types.clone(),
            post_body: fields.post_body.clone(),
            state: fields.state.clone(),
            triage_scores: None,
        }
    }
}

impl Match for BlockListHttp {
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
        "block list http"
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
