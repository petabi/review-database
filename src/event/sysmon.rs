#![allow(clippy::module_name_repetitions)]
use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{serde::ts_nanoseconds, DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

#[derive(Serialize, Deserialize)]
pub struct WindowsThreat {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for WindowsThreat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "-,-,-,-,-,Windows threat events,3,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.source,
            self.service,
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.user,
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

// TODO: Make new Match trait for Windows threat events
impl Match for WindowsThreat {
    fn source(&self) -> &str {
        &self.source
    }

    fn src_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn proto(&self) -> u8 {
        0
    }

    // TODO: choose event category with service and attack_kind value
    fn category(&self) -> EventCategory {
        EventCategory::Impact
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        &self.attack_kind
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}
