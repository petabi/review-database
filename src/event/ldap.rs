#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{LdapAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_ldap_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ldap(attr) = $raw_event_attr {
            let target_value = match attr {
                LdapAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                LdapAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                LdapAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                LdapAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                LdapAttr::Proto => AttrValue::UInt($event.proto.into()),
                LdapAttr::MessageId => AttrValue::UInt($event.message_id.into()),
                LdapAttr::Version => AttrValue::UInt($event.version.into()),
                LdapAttr::Opcode => AttrValue::VecString(&$event.opcode),
                LdapAttr::Result => AttrValue::VecString(&$event.result),
                LdapAttr::DiagnosticMessage => AttrValue::VecString(&$event.diagnostic_message),
                LdapAttr::Object => AttrValue::VecString(&$event.object),
                LdapAttr::Argument => AttrValue::VecString(&$event.argument),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForceFields {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl LdapBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_pw_list={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.to_string(),
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

fn get_user_pw_list(user_pw_list: &[(String, String)]) -> String {
    if user_pw_list.is_empty() {
        String::new()
    } else {
        user_pw_list
            .iter()
            .map(|(user, pw)| format!("{user}:{pw}"))
            .collect::<Vec<String>>()
            .join(",")
    }
}

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForce {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LdapBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_pw_list={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl LdapBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &LdapBruteForceFields) -> Self {
        LdapBruteForce {
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            user_pw_list: fields.user_pw_list.clone(),
            start_time: fields.start_time,
            end_time: fields.end_time,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LdapBruteForce {
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
        "ldap brute force"
    }

    fn sensor(&self) -> &'static str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        if let RawEventAttrKind::Ldap(attr) = raw_event_attr {
            match attr {
                LdapAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                LdapAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                LdapAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                LdapAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LdapEventFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl LdapEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor.to_string(),
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct LdapPlainText {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LdapPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl LdapPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            message_id: fields.message_id,
            version: fields.version,
            opcode: fields.opcode,
            result: fields.result,
            diagnostic_message: fields.diagnostic_message,
            object: fields.object,
            argument: fields.argument,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LdapPlainText {
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
        "ldap plain text"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_ldap_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistLdap {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistLdap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistLdap {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            message_id: fields.message_id,
            version: fields.version,
            opcode: fields.opcode,
            result: fields.result,
            diagnostic_message: fields.diagnostic_message,
            object: fields.object,
            argument: fields.argument,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistLdap {
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
        "blocklist ldap"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_ldap_attr_by_kind!(self, raw_event_attr)
    }
}
