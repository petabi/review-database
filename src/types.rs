use std::{cmp::Ordering, net::IpAddr, ops::RangeInclusive};

use anyhow::Result;
use chrono::{naive::serde::ts_nanoseconds_option, NaiveDateTime};
use ipnet::IpNet;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use strum_macros::Display;

use super::TrafficDirection;
pub use crate::account::{Account, Role};

pub trait FromKeyValue: Sized {
    /// Creates a new instance from the given key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or value cannot be deserialized.
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self>;
}

pub(crate) type Timestamp = i64;
pub(crate) type Source = String;
pub(crate) type Id = (Timestamp, Source);

pub struct PretrainedModel(pub Vec<u8>);

#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    Eq,
    Hash,
    PartialEq,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u8)]
pub enum EventCategory {
    Reconnaissance = 1,
    InitialAccess,
    Execution,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
    HttpThreat,
}

#[derive(Deserialize)]
pub struct Cluster {
    pub id: i32,
    pub cluster_id: String,
    pub category_id: i32,
    pub detector_id: i32,
    pub event_ids: Vec<Timestamp>,
    pub event_sources: Vec<Source>,
    pub labels: Option<Vec<String>>,
    pub qualifier_id: i32,
    pub status_id: i32,
    pub signature: String,
    pub size: i64,
    pub score: Option<f64>,
    #[serde(with = "ts_nanoseconds_option")]
    pub last_modification_time: Option<NaiveDateTime>,
    pub model_id: i32,
}

#[derive(Deserialize, Serialize)]
pub struct Endpoint {
    pub direction: Option<TrafficDirection>,
    pub network: HostNetworkGroup,
}

// `hosts` and `networks` must be kept sorted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    hosts: Vec<IpAddr>,
    networks: Vec<IpNet>,
    ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

impl HostNetworkGroup {
    #[must_use]
    pub fn new(
        mut hosts: Vec<IpAddr>,
        mut networks: Vec<IpNet>,
        mut ip_ranges: Vec<RangeInclusive<IpAddr>>,
    ) -> Self {
        hosts.sort_unstable();
        hosts.dedup();
        networks.sort_unstable();
        networks.dedup();
        ip_ranges.sort_unstable_by(|a, b| match a.start().cmp(b.start()) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => a.end().cmp(b.end()),
            Ordering::Greater => Ordering::Greater,
        });
        ip_ranges.dedup();
        Self {
            hosts,
            networks,
            ip_ranges,
        }
    }

    #[must_use]
    pub fn hosts(&self) -> &[IpAddr] {
        &self.hosts
    }

    #[must_use]
    pub fn ip_ranges(&self) -> &[RangeInclusive<IpAddr>] {
        &self.ip_ranges
    }

    #[must_use]
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        if self.contains_host(addr) {
            return true;
        }

        if self.networks.iter().any(|net| net.contains(&addr)) {
            return true;
        }

        if self.ip_ranges.iter().any(|range| range.contains(&addr)) {
            return true;
        }

        false
    }

    #[must_use]
    pub fn contains_host(&self, host: IpAddr) -> bool {
        self.hosts.binary_search(&host).is_ok()
    }

    #[must_use]
    pub fn contains_ip_range(&self, ip_range: &RangeInclusive<IpAddr>) -> bool {
        self.ip_ranges.contains(ip_range)
    }

    #[must_use]
    pub fn contains_network(&self, network: &IpNet) -> bool {
        self.networks.binary_search(network).is_ok()
    }
}

#[derive(Deserialize)]
pub struct Outlier {
    pub id: i32,
    #[serde(with = "serde_bytes")]
    pub raw_event: Vec<u8>,
    pub event_ids: Vec<Timestamp>,
    pub event_sources: Vec<Source>,
    pub size: i64,
    pub model_id: i32,
}

pub type SeqNo = usize;
pub type ModelScores = std::collections::HashMap<SeqNo, f64>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct ModelBatchInfo {
    pub id: i64,
    pub earliest: i64,
    pub latest: i64,
    pub size: usize,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Status {
    pub id: u32,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Qualifier {
    pub id: u32,
    pub description: String,
}
