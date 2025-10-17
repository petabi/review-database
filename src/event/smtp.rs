use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RawEventAttrKind, SmtpAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    migration::MigrateFrom,
    types::EventCategoryV0_41,
};

macro_rules! find_smtp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Smtp(attr) = $raw_event_attr {
            let target_value = match attr {
                SmtpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                SmtpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                SmtpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                SmtpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                SmtpAttr::Proto => AttrValue::UInt($event.proto.into()),
                SmtpAttr::MailFrom => AttrValue::String(&$event.mailfrom),
                SmtpAttr::Date => AttrValue::String(&$event.date),
                SmtpAttr::From => AttrValue::String(&$event.from),
                SmtpAttr::To => AttrValue::String(&$event.to),
                SmtpAttr::Subject => AttrValue::String(&$event.subject),
                SmtpAttr::Agent => AttrValue::String(&$event.agent),
                SmtpAttr::State => AttrValue::String(&$event.state),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistSmtpFields = BlocklistSmtpFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistSmtpFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl MigrateFrom<BlocklistSmtpFieldsV0_41> for BlocklistSmtpFieldsV0_42 {
    fn new(value: BlocklistSmtpFieldsV0_41, start_time: i64) -> Self {
        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            start_time,
            end_time: value.end_time,
            mailfrom: value.mailfrom,
            date: value.date,
            from: value.from,
            to: value.to,
            subject: value.subject,
            agent: value.agent,
            state: value.state,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSmtpFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}

impl BlocklistSmtpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();

        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?} confidence={:?}",
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
            start_time_str,
            end_time_str,
            self.mailfrom,
            self.date,
            self.from,
            self.to,
            self.subject,
            self.agent,
            self.state,
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistSmtp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistSmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();

        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            start_time_str,
            end_time_str,
            self.mailfrom,
            self.date,
            self.from,
            self.to,
            self.subject,
            self.agent,
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistSmtp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistSmtpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            start_time: fields.start_time,
            end_time: fields.end_time,
            mailfrom: fields.mailfrom,
            date: fields.date,
            from: fields.from,
            to: fields.to,
            subject: fields.subject,
            agent: fields.agent,
            state: fields.state,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistSmtp {
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
        "blocklist smtp"
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
        find_smtp_attr_by_kind!(self, raw_event_attr)
    }
}
