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
                HttpAttr::OrigFilenames => Some(AttrValue::VecString(&$event.filenames)),
                HttpAttr::OrigMimeTypes => Some(AttrValue::VecString(&$event.mime_types)),
                HttpAttr::RespFilenames => Some(AttrValue::VecString(&$event.filenames)),
                HttpAttr::RespMimeTypes => Some(AttrValue::VecString(&$event.mime_types)),
                HttpAttr::PostBody => Some(AttrValue::VecRaw(&$event.body)),
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
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
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
            filenames: {
                let mut filenames = value.orig_filenames;
                filenames.extend(value.resp_filenames);
                filenames
            },
            mime_types: {
                let mut mime_types = value.orig_mime_types;
                mime_types.extend(value.resp_mime_types);
                mime_types
            },
            body: value.post_body,
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
    pub start_time: DateTime<Utc>,
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
        Some(self.confidence)
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

pub type HttpThreatFields = HttpThreatFieldsV0_41;

impl HttpThreatFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatFieldsV0_41 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<HttpThreatFieldsV0_34> for HttpThreatFieldsV0_41 {
    fn from(value: HttpThreatFieldsV0_34) -> Self {
        Self {
            time: value.time,
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
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
            filenames: {
                let mut filenames = value.orig_filenames;
                filenames.extend(value.resp_filenames);
                filenames
            },
            mime_types: {
                let mut mime_types = value.orig_mime_types;
                mime_types.extend(value.resp_mime_types);
                mime_types
            },
            body: value.post_body,
            state: value.state,
            db_name: value.db_name,
            rule_id: value.rule_id,
            matched_to: value.matched_to,
            cluster_id: value.cluster_id,
            attack_kind: value.attack_kind,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatFieldsV0_34 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
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
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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
            filenames: fields.filenames,
            mime_types: fields.mime_types,
            body: fields.body,
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

pub type DgaFields = DgaFieldsV0_41;

impl DgaFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.confidence.to_string()
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DgaFieldsV0_41 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<DgaFieldsV0_40> for DgaFieldsV0_41 {
    fn from(value: DgaFieldsV0_40) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
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
            filenames: {
                let mut filenames = value.orig_filenames;
                filenames.extend(value.resp_filenames);
                filenames
            },
            mime_types: {
                let mut mime_types = value.orig_mime_types;
                mime_types.extend(value.resp_mime_types);
                mime_types
            },
            body: value.post_body,
            state: value.state,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DgaFieldsV0_40 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DomainGenerationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?} triage_scores={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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
            filenames: fields.filenames,
            mime_types: fields.mime_types,
            body: fields.body,
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for NonBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} triage_scores={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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
            filenames: fields.filenames.clone(),
            mime_types: fields.mime_types.clone(),
            body: fields.body.clone(),
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
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_http_attr_by_kind!(self, raw_event_attr)
    }
}

pub type BlocklistHttpFields = BlocklistHttpFieldsV0_41;

impl BlocklistHttpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.confidence.to_string(),
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlocklistHttpFieldsV0_41 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<BlocklistHttpFieldsV0_40> for BlocklistHttpFieldsV0_41 {
    fn from(value: BlocklistHttpFieldsV0_40) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
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
            filenames: {
                let mut filenames = value.orig_filenames;
                filenames.extend(value.resp_filenames);
                filenames
            },
            mime_types: {
                let mut mime_types = value.orig_mime_types;
                mime_types.extend(value.resp_mime_types);
                mime_types
            },
            body: value.post_body,
            state: value.state,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlocklistHttpFieldsV0_40 {
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
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} triage_scores={:?}",
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
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
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
            filenames: fields.filenames.clone(),
            mime_types: fields.mime_types.clone(),
            body: fields.body.clone(),
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::DateTime;

    use super::{EventCategory, HttpEventFieldsV0_39, HttpEventFieldsV0_41};

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_http_event_fields_migration_from_v0_39() {
        // Test case 1: Multiple orig files and mime types, single resp file and mime type
        let old_fields_case1 = HttpEventFieldsV0_39 {
            sensor: "test-sensor".to_string(),
            end_time: DateTime::UNIX_EPOCH,
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/test".to_string(),
            referer: "https://referer.com".to_string(),
            version: "1.1".to_string(),
            user_agent: "test-agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            cookie: "session=123".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            orig_filenames: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            orig_mime_types: vec!["text/plain".to_string(), "application/json".to_string()],
            resp_filenames: vec!["response1.html".to_string()],
            resp_mime_types: vec!["text/html".to_string()],
            post_body: b"test body content".to_vec(),
            state: "active".to_string(),
            category: EventCategory::InitialAccess,
        };

        let new_fields_case1: HttpEventFieldsV0_41 = old_fields_case1.into();

        // Verify that fields were merged correctly (orig + resp)
        assert_eq!(new_fields_case1.filenames.len(), 3); // 2 + 1
        assert_eq!(new_fields_case1.filenames[0], "file1.txt");
        assert_eq!(new_fields_case1.filenames[1], "file2.txt");
        assert_eq!(new_fields_case1.filenames[2], "response1.html");

        assert_eq!(new_fields_case1.mime_types.len(), 3); // 2 + 1
        assert_eq!(new_fields_case1.mime_types[0], "text/plain");
        assert_eq!(new_fields_case1.mime_types[1], "application/json");
        assert_eq!(new_fields_case1.mime_types[2], "text/html");

        // Verify that post_body was renamed to body
        assert_eq!(new_fields_case1.body, b"test body content".to_vec());
        assert_eq!(new_fields_case1.confidence, 1.0);

        // Test case 2: Single orig file, multiple resp files and mime types
        let old_fields_case2 = HttpEventFieldsV0_39 {
            sensor: "api-sensor".to_string(),
            end_time: DateTime::UNIX_EPOCH,
            src_addr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            src_port: 9090,
            dst_addr: "192.168.1.10".parse::<IpAddr>().unwrap(),
            dst_port: 443,
            proto: 6,
            method: "POST".to_string(),
            host: "api.example.com".to_string(),
            uri: "/api/v1/test".to_string(),
            referer: "https://app.example.com".to_string(),
            version: "2.0".to_string(),
            user_agent: "api-client".to_string(),
            request_len: 150,
            response_len: 300,
            status_code: 201,
            status_msg: "Created".to_string(),
            username: "apiuser".to_string(),
            password: "apipass".to_string(),
            cookie: "token=abc123".to_string(),
            content_encoding: "deflate".to_string(),
            content_type: "application/json".to_string(),
            cache_control: "max-age=3600".to_string(),
            orig_filenames: vec!["upload1.dat".to_string()],
            orig_mime_types: vec!["application/octet-stream".to_string()],
            resp_filenames: vec!["result.json".to_string(), "metadata.xml".to_string()],
            resp_mime_types: vec![
                "application/json".to_string(),
                "application/xml".to_string(),
            ],
            post_body: b"{\"key\":\"value\"}".to_vec(),
            state: "processing".to_string(),
            category: EventCategory::Collection,
        };

        let new_fields_case2: HttpEventFieldsV0_41 = old_fields_case2.into();

        // Verify migration worked correctly (orig + resp)
        assert_eq!(new_fields_case2.filenames.len(), 3); // 1 + 2
        assert_eq!(new_fields_case2.filenames[0], "upload1.dat");
        assert_eq!(new_fields_case2.filenames[1], "result.json");
        assert_eq!(new_fields_case2.filenames[2], "metadata.xml");

        assert_eq!(new_fields_case2.mime_types.len(), 3); // 1 + 2
        assert_eq!(new_fields_case2.mime_types[0], "application/octet-stream");
        assert_eq!(new_fields_case2.mime_types[1], "application/json");
        assert_eq!(new_fields_case2.mime_types[2], "application/xml");

        assert_eq!(new_fields_case2.body, b"{\"key\":\"value\"}".to_vec());
        assert_eq!(new_fields_case2.confidence, 1.0);
    }

    #[test]
    fn test_empty_collections_migration() {
        // Test migration with empty filename and mime type collections
        let old_fields = HttpEventFieldsV0_39 {
            sensor: "test-sensor".to_string(),
            end_time: DateTime::UNIX_EPOCH,
            src_addr: "127.0.0.1".parse::<IpAddr>().unwrap(),
            src_port: 3000,
            dst_addr: "127.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 8000,
            proto: 6,
            method: "HEAD".to_string(),
            host: "localhost".to_string(),
            uri: "/health".to_string(),
            referer: String::new(),
            version: "1.0".to_string(),
            user_agent: "health-check".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 204,
            status_msg: "No Content".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: "idle".to_string(),
            category: EventCategory::Discovery,
        };

        let new_fields: HttpEventFieldsV0_41 = old_fields.into();

        // Verify empty collections remain empty after merge
        assert!(new_fields.filenames.is_empty());
        assert!(new_fields.mime_types.is_empty());
        assert!(new_fields.body.is_empty());
    }
}
