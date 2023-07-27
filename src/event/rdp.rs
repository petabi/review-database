#![allow(clippy::module_name_repetitions)]

use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForceFields {
    pub src_addr: IpAddr,
    pub dst_addrs: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
}

impl fmt::Display for RdpBruteForceFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},-,-,-,{},RDP Brute Force,3,{},{}",
            self.src_addr, self.proto, self.start_time, self.last_time,
        )
    }
}

pub struct RdpBruteForce {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addrs: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RdpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},-,-,-,{},RDP Brute Force,{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.proto,
            self.start_time,
            self.last_time,
        )
    }
}

impl RdpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &RdpBruteForceFields) -> Self {
        RdpBruteForce {
            time,
            src_addr: fields.src_addr,
            dst_addrs: fields.dst_addrs.clone(),
            start_time: fields.start_time,
            last_time: fields.last_time,
            proto: fields.proto,
            triage_scores: None,
        }
    }
}

impl Match for RdpBruteForce {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
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
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Exfiltration
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "rdp brute force"
    }

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn score_by_packet_attr(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }
}
