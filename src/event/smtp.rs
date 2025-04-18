use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RawEventAttrKind, SmtpAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! smtp_target_attr {
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

#[derive(Serialize, Deserialize)]
pub struct BlockListSmtpFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub category: EventCategory,
}

impl fmt::Display for BlockListSmtpFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.mailfrom,
            self.date,
            self.from,
            self.to,
            self.subject,
            self.agent,
            self.state
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListSmtp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlockListSmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
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

impl BlockListSmtp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListSmtpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            mailfrom: fields.mailfrom,
            date: fields.date,
            from: fields.from,
            to: fields.to,
            subject: fields.subject,
            agent: fields.agent,
            state: fields.state,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListSmtp {
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
        "block list stmp"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn to_attr_value(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        smtp_target_attr!(self, raw_event_attr)
    }
}
