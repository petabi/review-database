#![allow(clippy::module_name_repetitions)]
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU8,
};

use chrono::{serde::ts_nanoseconds, DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, PartialEq, EnumString)]
pub enum LogAttr {
    #[strum(serialize = "log-content")]
    Content,
}

#[derive(Serialize, Deserialize)]
pub struct ExtraThreat {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub service: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for ExtraThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} service={:?} content={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
            self.source,
            self.service,
            self.content,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.to_string(),
            self.attack_kind,
            self.confidence.to_string(),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl Match<LogAttr> for ExtraThreat {
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

    fn category(&self) -> EventCategory {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &str {
        "extra threat"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn target_attribute(&self, proto_attr: LogAttr) -> Option<AttrValue> {
        if proto_attr == LogAttr::Content {
            return Some(AttrValue::String(&self.content));
        }
        None
    }
}
