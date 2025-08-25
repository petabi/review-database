use std::{fmt, net::IpAddr, num::NonZeroU8};

use aho_corasick::AhoCorasickBuilder;
use attrievent::attribute::{HttpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, EventFilter, LOW, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_http_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {
        if let RawEventAttrKind::Http(attr) = $raw_event_attr {
            match attr {
                HttpAttr::SrcAddr => Some(AttrValue::Addr($event.src_addr)),
                HttpAttr::SrcPort => Some(AttrValue::UInt($event.src_port.into())),
                HttpAttr::DstAddr => Some(AttrValue::Addr($event.dst_addr)),
                HttpAttr::DstPort => Some(AttrValue::UInt($event.dst_port.into())),
                HttpAttr::Proto => Some(AttrValue::UInt($event.proto.into())),
                HttpAttr::Method => Some(AttrValue::String(&$event.method)),
                HttpAttr::Host => Some(AttrValue::String(&$event.host)),
                HttpAttr::Uri => Some(AttrValue::String(&$event.uri)),
                HttpAttr::Referer => Some(AttrValue::String(&$event.referer)),
                HttpAttr::Version => Some(AttrValue::String(&$event.version)),
                HttpAttr::UserAgent => Some(AttrValue::String(&$event.user_agent)),
                HttpAttr::RequestLen => u64::try_from($event.request_len).ok().map(AttrValue::UInt),
                HttpAttr::ResponseLen => {
                    u64::try_from($event.response_len).ok().map(AttrValue::UInt)
                }
                HttpAttr::StatusCode => Some(AttrValue::UInt($event.status_code.into())),
                HttpAttr::StatusMsg => Some(AttrValue::String(&$event.status_msg)),
                HttpAttr::Username => Some(AttrValue::String(&$event.username)),
                HttpAttr::Password => Some(AttrValue::String(&$event.password)),
                HttpAttr::Cookie => Some(AttrValue::String(&$event.cookie)),
                HttpAttr::ContentEncoding => Some(AttrValue::String(&$event.content_encoding)),
                HttpAttr::ContentType => Some(AttrValue::String(&$event.content_type)),
                HttpAttr::CacheControl => Some(AttrValue::String(&$event.cache_control)),
                HttpAttr::OrigFilenames => Some(AttrValue::VecString(&$event.orig_filenames)),
                HttpAttr::OrigMimeTypes => Some(AttrValue::VecString(&$event.orig_mime_types)),
                HttpAttr::RespFilenames => Some(AttrValue::VecString(&$event.resp_filenames)),
                HttpAttr::RespMimeTypes => Some(AttrValue::VecString(&$event.resp_mime_types)),
                HttpAttr::PostBody => Some(AttrValue::VecRaw(&$event.post_body)),
                HttpAttr::State => Some(AttrValue::String(&$event.state)),
            }
        } else {
            None
        }
    };
}
pub(super) use find_http_attr_by_kind;

pub type HttpEventFields = HttpEventFieldsV0_41;

impl HttpEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct HttpEventFieldsV0_41 {
    pub sensor: String,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
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
    pub category: EventCategory,
}

impl From<HttpEventFieldsV0_39> for HttpEventFieldsV0_41 {
    fn from(value: HttpEventFieldsV0_39) -> Self {
        Self {
            sensor: value.sensor,
            end_time: value.end_time,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            method: value.method,
            host: value.host,
            uri: value.uri,
            referer: value.referer,
            version: value.version,
            user_agent: value.user_agent,
            request_len: value.request_len,
            response_len: value.response_len,
            status_code: value.status_code,
            status_msg: value.status_msg,
            username: value.username,
            password: value.password,
            cookie: value.cookie,
            content_encoding: value.content_encoding,
            content_type: value.content_type,
            cache_control: value.cache_control,
            orig_filenames: value.orig_filenames,
            orig_mime_types: value.orig_mime_types,
            resp_filenames: value.resp_filenames,
            resp_mime_types: value.resp_mime_types,
            post_body: value.post_body,
            state: value.state,
            confidence: 1.0, // default value for HTTP events
            category: value.category,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct HttpEventFieldsV0_39 {
    pub sensor: String,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
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
    pub category: EventCategory,
}

pub type RepeatedHttpSessionsFields = RepeatedHttpSessionsFieldsV0_41;

impl RepeatedHttpSessionsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessionsFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<RepeatedHttpSessionsFieldsV0_39> for RepeatedHttpSessionsFieldsV0_41 {
    fn from(value: RepeatedHttpSessionsFieldsV0_39) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time: DateTime::UNIX_EPOCH,
            end_time: DateTime::UNIX_EPOCH,
            confidence: 0.3, // default value for RepeatedHttpSessions
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessionsFieldsV0_39 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub category: EventCategory,
}

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessions {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub start_time: DateTime<Utc>,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RepeatedHttpSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl RepeatedHttpSessions {
    pub(super) fn new(time: DateTime<Utc>, fields: &RepeatedHttpSessionsFields) -> Self {
        RepeatedHttpSessions {
            time,
            sensor: fields.sensor.clone(),
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            start_time: fields.start_time,
            end_time: fields.end_time,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for RepeatedHttpSessions {
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

    fn level(&self) -> std::num::NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "repeated http sessions"
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
        if let RawEventAttrKind::Http(attr) = raw_event_attr {
            match attr {
                HttpAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                HttpAttr::SrcPort => Some(AttrValue::UInt(self.src_port.into())),
                HttpAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                HttpAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                HttpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatFields {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl HttpThreatFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            chrono::DateTime::from_timestamp_nanos(self.end_time).to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string(),
        )
    }
}

// HTTP Request body has Vec<u8> type, and it's too large to print.
const MAX_POST_BODY_LEN: usize = 10;
pub(super) fn get_post_body(post_body: &[u8]) -> String {
    let post_body = String::from_utf8_lossy(post_body);
    if post_body.len() > MAX_POST_BODY_LEN {
        let mut trimmed = post_body
            .get(..MAX_POST_BODY_LEN)
            .map_or(String::new(), ToString::to_string);
        trimmed.push_str("...");
        trimmed
    } else {
        post_body.to_string()
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreat {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for HttpThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl HttpThreat {
    pub(super) fn new(time: DateTime<Utc>, fields: HttpThreatFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for HttpThreat {
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
        LOW
    }

    fn kind(&self) -> &'static str {
        "http threat"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        if let Some(kinds) = &filter.kinds {
            let patterns = self
                .attack_kind
                .split_whitespace()
                .filter(|s| s.chars().any(char::is_alphanumeric))
                .map(ToString::to_string)
                .collect::<Vec<String>>();
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(patterns)
                .expect("automatic build should not fail");
            if kinds.iter().all(|kind| {
                let words = kind
                    .split_whitespace()
                    .filter(|s| s.chars().any(char::is_alphanumeric))
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
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub category: EventCategory,
}

impl DgaFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct DomainGenerationAlgorithm {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DomainGenerationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl DomainGenerationAlgorithm {
    pub(super) fn new(time: DateTime<Utc>, fields: DgaFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for DomainGenerationAlgorithm {
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
        LOW
    }

    fn kind(&self) -> &'static str {
        "dga"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct NonBrowser {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for NonBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl NonBrowser {
    pub(super) fn new(time: DateTime<Utc>, fields: &HttpEventFields) -> Self {
        NonBrowser {
            time,
            sensor: fields.sensor.clone(),
            end_time: fields.end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
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
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for NonBrowser {
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
        "non browser"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlocklistHttpFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub category: EventCategory,
}

impl BlocklistHttpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct BlocklistHttp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistHttp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistHttpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
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
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistHttp {
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
        "blocklist http"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }
}
