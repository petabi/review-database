use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{DateTime, Local, Utc};
use serde::Deserialize;
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Deserialize)]
pub(super) struct TorConnectionFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
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
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
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
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
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
