use super::{common::Match, EventCategory, TriagePolicy, TriageScore, MEDIUM};
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

#[derive(Serialize, Deserialize)]
pub struct PortScanFields {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
}

impl fmt::Display for PortScanFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},-,{},-,{},Port Scan,3,{},{}",
            self.src_addr, self.dst_addr, self.proto, self.start_time, self.last_time,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct PortScan {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},-,{},-,{},Port Scan,{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.dst_addr,
            self.proto,
            self.start_time,
            self.last_time,
        )
    }
}

impl PortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &PortScanFields) -> Self {
        PortScan {
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_ports: fields.dst_ports.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for PortScan {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    fn dst_port(&self) -> u16 {
        0
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

    fn kind(&self) -> &'static str {
        "port scan"
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

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFields {
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl fmt::Display for MultiHostPortScanFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},-,-,{},{},Multi Host Port Scan,3,{},{}",
            self.src_addr, self.dst_port, self.proto, self.start_time, self.last_time,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct MultiHostPortScan {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for MultiHostPortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},{},-,-,{},{},Multi Host Port Scan,{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.src_addr,
            self.dst_port,
            self.proto,
            self.start_time,
            self.last_time,
        )
    }
}

impl MultiHostPortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &MultiHostPortScanFields) -> Self {
        MultiHostPortScan {
            time,
            src_addr: fields.src_addr,
            dst_port: fields.dst_port,
            dst_addrs: fields.dst_addrs.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for MultiHostPortScan {
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
        self.dst_port
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

    fn kind(&self) -> &'static str {
        "multi host port scan"
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

#[derive(Serialize, Deserialize)]
pub struct ExternalDDosFields {
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl fmt::Display for ExternalDDosFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "-,-,{},-,{},External DDos,3,{},{}",
            self.dst_addr, self.proto, self.start_time, self.last_time,
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct ExternalDDos {
    pub time: DateTime<Utc>,
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for ExternalDDos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{},-,-,{},-,{},External DDos,{},{}",
            DateTime::<Local>::from(self.time).format("%Y-%m-%d %H:%M:%S"),
            self.dst_addr,
            self.proto,
            self.start_time,
            self.last_time,
        )
    }
}

impl ExternalDDos {
    pub(super) fn new(time: DateTime<Utc>, fields: &ExternalDDosFields) -> Self {
        ExternalDDos {
            time,
            src_addrs: fields.src_addrs.clone(),
            dst_addr: fields.dst_addr,
            proto: fields.proto,
            start_time: fields.start_time,
            last_time: fields.last_time,
            triage_scores: None,
        }
    }
}

impl Match for ExternalDDos {
    fn src_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> EventCategory {
        EventCategory::Impact
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "external ddos"
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
