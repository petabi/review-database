use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::RawEventAttrKind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

#[derive(Serialize, Deserialize)]
pub struct BlocklistDceRpcFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl BlocklistDceRpcFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation,
            self.confidence.to_string()
        )
    }
}

pub struct BlocklistDceRpc {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDceRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistDceRpc {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDceRpcFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            rtt: fields.rtt,
            named_pipe: fields.named_pipe,
            endpoint: fields.endpoint,
            operation: fields.operation,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDceRpc {
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
        "blocklist dcerpc"
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

    // Since `dcerpc` is not currently an event type collected by Feature Sensor, and as a result,
    // the notation for each attribute of `dcerpc` has not been finalized. Therefore, we will
    // proceed with this part after the collection and notation of dcerpc events is finalized.
    fn find_attr_by_kind(&self, _raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        None
    }
}
