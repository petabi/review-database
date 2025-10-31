use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::RawEventAttrKind;
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    migration::MigrateFrom,
    types::EventCategoryV0_41,
};

pub type BlocklistDceRpcFields = BlocklistDceRpcFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistDceRpcFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub start_time: DateTime<Utc>,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl MigrateFrom<BlocklistDceRpcFieldsV0_41> for BlocklistDceRpcFieldsV0_42 {
    fn new(value: BlocklistDceRpcFieldsV0_41, start_time: i64) -> Self {
        let start_time_dt = chrono::DateTime::from_timestamp_nanos(start_time);
        let end_time_nanos = value.end_time;
        let end_time_dt = chrono::DateTime::from_timestamp_nanos(end_time_nanos);
        let duration = end_time_nanos.saturating_sub(start_time);

        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time: start_time_dt,
            end_time: end_time_dt,
            duration,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            rtt: value.rtt,
            named_pipe: value.named_pipe,
            endpoint: value.endpoint,
            operation: value.operation,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistDceRpcFieldsV0_41 {
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
    pub category: EventCategoryV0_41,
}

impl BlocklistDceRpcFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
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
    pub start_time: i64,
    pub end_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDceRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            start_time_str,
            end_time_str,
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
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
            start_time: fields.start_time.timestamp_nanos_opt().unwrap_or_default(),
            end_time: fields.end_time.timestamp_nanos_opt().unwrap_or_default(),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
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

    fn category(&self) -> Option<EventCategory> {
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
