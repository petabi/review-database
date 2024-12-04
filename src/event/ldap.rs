#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{common::Match, EventCategory, TriageScore, MEDIUM};
use crate::event::common::{triage_scores_to_string, AttrValue};

macro_rules! ldap_target_attr {
    ($event: expr, $proto_attr: expr) => {{
        let target_value = match $proto_attr {
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
    }};
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, EnumString, PartialEq)]
pub enum LdapAttr {
    #[strum(serialize = "ldap-id.orig_h")]
    SrcAddr,
    #[strum(serialize = "ldap-id.orig_p")]
    SrcPort,
    #[strum(serialize = "ldap-id.resp_h")]
    DstAddr,
    #[strum(serialize = "ldap-id.resp_p")]
    DstPort,
    #[strum(serialize = "ldap-proto")]
    Proto,
    #[strum(serialize = "ldap-message_id")]
    MessageId,
    #[strum(serialize = "ldap-version")]
    Version,
    #[strum(serialize = "ldap-opcode")]
    Opcode,
    #[strum(serialize = "ldap-result")]
    Result,
    #[strum(serialize = "ldap-diagnostic_message")]
    DiagnosticMessage,
    #[strum(serialize = "ldap-object")]
    Object,
    #[strum(serialize = "ldap-argument")]
    Argument,
}

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForceFields {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub category: EventCategory,
}

impl fmt::Display for LdapBruteForceFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_pw_list={:?} start_time={:?} last_time={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339()
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

pub struct LdapBruteForce {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LdapBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_pw_list={:?} start_time={:?} last_time={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            self.start_time.to_rfc3339(),
            self.last_time.to_rfc3339(),
            triage_scores_to_string(&self.triage_scores)
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
            last_time: fields.last_time,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match<LdapAttr> for LdapBruteForce {
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

    fn source(&self) -> &str {
        "-"
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: LdapAttr) -> Option<AttrValue> {
        match proto_attr {
            LdapAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
            LdapAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
            LdapAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
            LdapAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LdapEventFields {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub category: EventCategory,
}

impl fmt::Display for LdapEventFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(",")
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct LdapPlainText {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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

impl fmt::Display for LdapPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl LdapPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
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

impl Match<LdapAttr> for LdapPlainText {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
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

    fn kind(&self) -> &str {
        "ldap plain text"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: LdapAttr) -> Option<AttrValue> {
        ldap_target_attr!(self, proto_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListLdap {
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
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

impl fmt::Display for BlockListLdap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
            self.source,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(&self.triage_scores)
        )
    }
}

impl BlockListLdap {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
        Self {
            time,
            source: fields.source,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
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

impl Match<LdapAttr> for BlockListLdap {
    fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addr(&self) -> IpAddr {
        self.dst_addr
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

    fn kind(&self) -> &str {
        "block list ldap"
    }

    fn source(&self) -> &str {
        self.source.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        None
    }

    fn target_attribute(&self, proto_attr: LdapAttr) -> Option<AttrValue> {
        ldap_target_attr!(self, proto_attr)
    }
}
