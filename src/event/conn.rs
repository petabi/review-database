use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string, vector_to_string},
    migration::MigrateFrom,
    types::EventCategoryV0_41,
};

macro_rules! find_conn_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Conn(attr) = $raw_event_attr {
            let target_value = match attr {
                ConnAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                ConnAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                ConnAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                ConnAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                ConnAttr::Proto => AttrValue::UInt($event.proto.into()),
                ConnAttr::ConnState => AttrValue::String(&$event.conn_state),
                ConnAttr::Duration => AttrValue::SInt(
                    $event.end_time - $event.time.timestamp_nanos_opt().unwrap_or_default(),
                ),
                ConnAttr::Service => AttrValue::String(&$event.service),
                ConnAttr::OrigBytes => AttrValue::UInt($event.orig_bytes),
                ConnAttr::RespBytes => AttrValue::UInt($event.resp_bytes),
                ConnAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                ConnAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                ConnAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                ConnAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type PortScanFields = PortScanFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct PortScanFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl PortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} dst_addr={:?} dst_ports={:?} start_time={:?} end_time={:?} proto={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            vector_to_string(&self.dst_ports),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.proto.to_string(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PortScanFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub proto: u8,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}
impl From<PortScanFieldsV0_41> for PortScanFieldsV0_42 {
    fn from(value: PortScanFieldsV0_41) -> Self {
        Self {
            sensor: String::new(),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            dst_ports: value.dst_ports,
            start_time: value.start_time,
            end_time: value.end_time,
            proto: value.proto,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct PortScan {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_ports={:?} start_time={:?} end_time={:?} proto={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            vector_to_string(&self.dst_ports),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl PortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &PortScanFields) -> Self {
        PortScan {
            sensor: fields.sensor.clone(),
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_ports: fields.dst_ports.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            end_time: fields.end_time,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for PortScan {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        0
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
        "port scan"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                ConnAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                ConnAttr::DstPort => Some(AttrValue::VecUInt(
                    self.dst_ports.iter().map(|val| u64::from(*val)).collect(),
                )),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type MultiHostPortScanFields = MultiHostPortScanFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl MultiHostPortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} dst_addrs={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MultiHostPortScanFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl From<MultiHostPortScanFieldsV0_41> for MultiHostPortScanFieldsV0_42 {
    fn from(value: MultiHostPortScanFieldsV0_41) -> Self {
        Self {
            sensor: String::new(),
            src_addr: value.src_addr,
            dst_port: value.dst_port,
            dst_addrs: value.dst_addrs,
            proto: value.proto,
            start_time: value.start_time,
            end_time: value.end_time,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScan {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for MultiHostPortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addrs={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            vector_to_string(&self.dst_addrs),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl MultiHostPortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &MultiHostPortScanFields) -> Self {
        MultiHostPortScan {
            sensor: fields.sensor.clone(),
            time,
            src_addr: fields.src_addr,
            dst_port: fields.dst_port,
            dst_addrs: fields.dst_addrs.clone(),
            proto: fields.proto,
            start_time: fields.start_time,
            end_time: fields.end_time,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for MultiHostPortScan {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        &self.dst_addrs
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
        "multi host port scan"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                ConnAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                ConnAttr::DstAddr => Some(AttrValue::VecAddr(&self.dst_addrs)),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type ExternalDdosFields = ExternalDdosFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct ExternalDdosFieldsV0_42 {
    pub sensor: String,
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl ExternalDdosFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addrs={:?} dst_addr={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            vector_to_string(&self.src_addrs),
            self.dst_addr.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExternalDdosFieldsV0_41 {
    pub sensor: String,
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}
impl From<ExternalDdosFieldsV0_41> for ExternalDdosFieldsV0_42 {
    fn from(value: ExternalDdosFieldsV0_41) -> Self {
        Self {
            sensor: String::new(),
            src_addrs: value.src_addrs,
            dst_addr: value.dst_addr,
            proto: value.proto,
            start_time: value.start_time,
            end_time: value.end_time,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct ExternalDdos {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for ExternalDdos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "src_addrs={:?} dst_addr={:?} proto={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            vector_to_string(&self.src_addrs),
            self.dst_addr.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl ExternalDdos {
    pub(super) fn new(time: DateTime<Utc>, fields: &ExternalDdosFields) -> Self {
        ExternalDdos {
            sensor: fields.sensor.clone(),
            time,
            src_addrs: fields.src_addrs.clone(),
            dst_addr: fields.dst_addr,
            proto: fields.proto,
            start_time: fields.start_time,
            end_time: fields.end_time,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for ExternalDdos {
    fn src_addrs(&self) -> &[IpAddr] {
        &self.src_addrs
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        0
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
        "external ddos"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::VecAddr(&self.src_addrs)),
                ConnAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type BlocklistConnFields = BlocklistConnFieldsV0_42;

#[derive(Deserialize, Serialize)]
pub struct BlocklistConnFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub end_time: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistConnFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub end_time: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistConnFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();

        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} conn_state={:?} start_time={:?} end_time={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} confidence={:?}",
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
            self.conn_state,
            start_time_str,
            end_time_str,
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.confidence.to_string(),
        )
    }
}

impl MigrateFrom<BlocklistConnFieldsV0_41> for BlocklistConnFieldsV0_42 {
    fn new(value: BlocklistConnFieldsV0_41, start_time: i64) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            conn_state: value.conn_state,
            start_time,
            end_time: value.end_time,
            service: value.service,
            orig_bytes: value.orig_bytes,
            resp_bytes: value.resp_bytes,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistConn {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub end_time: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();

        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} conn_state={:?} start_time={:?} end_time={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            start_time_str,
            end_time_str,
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistConn {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistConnFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            conn_state: fields.conn_state,
            start_time: fields.start_time,
            end_time: fields.end_time,
            service: fields.service,
            orig_bytes: fields.orig_bytes,
            resp_bytes: fields.resp_bytes,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistConn {
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
        "blocklist conn"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_conn_attr_by_kind!(self, raw_event_attr)
    }
}
