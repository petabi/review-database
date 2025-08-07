use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{KerberosAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_kerberos_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Kerberos(attr) = $raw_event_attr {
            let target_value = match attr {
                KerberosAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                KerberosAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                KerberosAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                KerberosAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                KerberosAttr::Proto => AttrValue::UInt($event.proto.into()),
                KerberosAttr::ClientTime => AttrValue::SInt($event.client_time),
                KerberosAttr::ServerTime => AttrValue::SInt($event.server_time),
                KerberosAttr::ErrorCode => AttrValue::UInt($event.error_code.into()),
                KerberosAttr::ClientRealm => AttrValue::String(&$event.client_realm),
                KerberosAttr::CnameType => AttrValue::UInt($event.cname_type.into()),
                KerberosAttr::ClientName => AttrValue::VecString(&$event.client_name),
                KerberosAttr::Realm => AttrValue::String(&$event.realm),
                KerberosAttr::SnameType => AttrValue::UInt($event.sname_type.into()),
                KerberosAttr::ServiceName => AttrValue::VecString(&$event.service_name),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistKerberosFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
}

impl BlocklistKerberosFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(","),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistKerberos {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistKerberos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_string(),
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistKerberos {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistKerberosFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            end_time: fields.end_time,
            client_time: fields.client_time,
            server_time: fields.server_time,
            error_code: fields.error_code,
            client_realm: fields.client_realm,
            cname_type: fields.cname_type,
            client_name: fields.client_name,
            realm: fields.realm,
            sname_type: fields.sname_type,
            service_name: fields.service_name,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistKerberos {
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
        "blocklist kerberos"
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
        find_kerberos_attr_by_kind!(self, raw_event_attr)
    }
}
