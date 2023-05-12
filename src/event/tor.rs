use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct TorConnectionFields {
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
}

impl fmt::Display for TorConnectionFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},Tor Exit Nodes,3",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto
        )
    }
}

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
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},Tor Exit Nodes",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto
        )
    }
}

impl TorConnection {
    pub(super) fn new(time: DateTime<Utc>, fields: &TorConnectionFields) -> Self {
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
        EventCategory::CommandAndControl
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        "tor exit node"
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
