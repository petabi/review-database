#![allow(clippy::module_name_repetitions)]
use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, num::NonZeroU8};

#[derive(Serialize, Deserialize)]
pub struct NetworkThreat {
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub service: String,
    pub last_time: i64,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for NetworkThreat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},NetworkThreat,{},{},{},{},{},{},{},{},{}",
            DateTime::<Local>::from(self.timestamp).format("%Y-%m-%d %H:%M:%S"),
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            self.service,
            self.last_time,
            self.content,
            self.db_name,
            self.rule_id,
            self.matched_to,
            self.cluster_id,
            self.attack_kind,
            self.confidence,
        )
    }
}

impl Match for NetworkThreat {
    fn src_addr(&self) -> IpAddr {
        self.orig_addr
    }

    fn src_port(&self) -> u16 {
        self.orig_port
    }

    fn dst_addr(&self) -> IpAddr {
        self.resp_addr
    }

    fn dst_port(&self) -> u16 {
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Reconnaissance
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        "NetworkThreat"
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
