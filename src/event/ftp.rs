#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{FtpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_ftp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ftp(attr) = $raw_event_attr {
            let target_value = match attr {
                FtpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                FtpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                FtpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                FtpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                FtpAttr::Proto => AttrValue::UInt($event.proto.into()),
                FtpAttr::User => AttrValue::String(&$event.user),
                FtpAttr::Password => AttrValue::String(&$event.password),
                FtpAttr::Command => AttrValue::String(&$event.command),
                FtpAttr::ReplyCode => AttrValue::String(&$event.reply_code),
                FtpAttr::ReplyMsg => AttrValue::String(&$event.reply_msg),
                FtpAttr::DataPassive => AttrValue::Bool($event.data_passive),
                FtpAttr::DataOrigAddr => AttrValue::Addr($event.data_orig_addr),
                FtpAttr::DataRespAddr => AttrValue::Addr($event.data_resp_addr),
                FtpAttr::DataRespPort => AttrValue::UInt($event.data_resp_port.into()),
                FtpAttr::File => AttrValue::String(&$event.file),
                FtpAttr::FileSize => AttrValue::UInt($event.file_size),
                FtpAttr::FileId => AttrValue::String(&$event.file_id),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceFields {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub is_internal: bool,
    pub category: EventCategory,
}

impl FtpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?}",
            self.category.to_string(),
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.is_internal.to_string()
        )
    }
}

pub struct FtpBruteForce {
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub is_internal: bool,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.is_internal.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &FtpBruteForceFields) -> Self {
        FtpBruteForce {
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            user_list: fields.user_list.clone(),
            start_time: fields.start_time,
            end_time: fields.end_time,
            is_internal: fields.is_internal,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpBruteForce {
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
        "ftp brute force"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        if let RawEventAttrKind::Ftp(attr) = raw_event_attr {
            match attr {
                FtpAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                FtpAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                FtpAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                FtpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                FtpAttr::User => Some(AttrValue::VecString(&self.user_list)),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FtpEventFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
    pub category: EventCategory,
}

impl FtpEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} user={:?} password={:?} command={:?} reply_code={:?} reply_msg={:?} data_passive={:?} data_orig_addr={:?} data_resp_addr={:?} data_resp_port={:?} file={:?} file_size={:?} file_id={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.user,
            self.password,
            self.command,
            self.reply_code,
            self.reply_msg,
            self.data_passive.to_string(),
            self.data_orig_addr.to_string(),
            self.data_resp_addr.to_string(),
            self.data_resp_port.to_string(),
            self.file,
            self.file_size.to_string(),
            self.file_id,
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct FtpPlainText {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} user={:?} password={:?} command={:?} reply_code={:?} reply_msg={:?} data_passive={:?} data_orig_addr={:?} data_resp_addr={:?} data_resp_port={:?} file={:?} file_size={:?} file_id={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.user,
            self.password,
            self.command,
            self.reply_code,
            self.reply_msg,
            self.data_passive.to_string(),
            self.data_orig_addr.to_string(),
            self.data_resp_addr.to_string(),
            self.data_resp_port.to_string(),
            self.file,
            self.file_size.to_string(),
            self.file_id,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            user: fields.user,
            password: fields.password,
            command: fields.command,
            reply_code: fields.reply_code,
            reply_msg: fields.reply_msg,
            data_passive: fields.data_passive,
            data_orig_addr: fields.data_orig_addr,
            data_resp_addr: fields.data_resp_addr,
            data_resp_port: fields.data_resp_port,
            file: fields.file,
            file_size: fields.file_size,
            file_id: fields.file_id,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpPlainText {
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
        "ftp plain text"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        find_ftp_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistFtp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistFtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} user={:?} password={:?} command={:?} reply_code={:?} reply_msg={:?} data_passive={:?} data_orig_addr={:?} data_resp_addr={:?} data_resp_port={:?} file={:?} file_size={:?} file_id={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.user,
            self.password,
            self.command,
            self.reply_code,
            self.reply_msg,
            self.data_passive.to_string(),
            self.data_orig_addr.to_string(),
            self.data_resp_addr.to_string(),
            self.data_resp_port.to_string(),
            self.file,
            self.file_size.to_string(),
            self.file_id,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistFtp {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            user: fields.user,
            password: fields.password,
            command: fields.command,
            reply_code: fields.reply_code,
            reply_msg: fields.reply_msg,
            data_passive: fields.data_passive,
            data_orig_addr: fields.data_orig_addr,
            data_resp_addr: fields.data_resp_addr,
            data_resp_port: fields.data_resp_port,
            file: fields.file,
            file_size: fields.file_size,
            file_id: fields.file_id,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistFtp {
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
        "blocklist ftp"
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

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue> {
        find_ftp_attr_by_kind!(self, raw_event_attr)
    }
}
