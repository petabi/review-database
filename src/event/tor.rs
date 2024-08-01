use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};

use super::{common::Match, EventCategory, HttpEventFields, TriagePolicy, TriageScore, MEDIUM};
use crate::event::{common::triage_scores_to_string, http::get_post_body};

#[allow(clippy::module_name_repetitions)]
pub struct TorConnection {
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} session_end_time={:?} method={:?} host={:?} uri={:?} referrer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.session_end_time.to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referrer,
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
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl TorConnection {
    pub(super) fn new(time: DateTime<Utc>, fields: &HttpEventFields) -> Self {
        TorConnection {
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
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for TorConnection {
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
        "tor exit nodes"
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
