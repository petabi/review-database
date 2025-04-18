use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{MqttAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! mqtt_target_attr {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Mqtt(attr) = $raw_event_attr {
            let target_value = match attr {
                MqttAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                MqttAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                MqttAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                MqttAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                MqttAttr::Proto => AttrValue::UInt($event.proto.into()),
                MqttAttr::Protocol => AttrValue::String(&$event.protocol),
                MqttAttr::Version => AttrValue::UInt($event.version.into()),
                MqttAttr::ClientId => AttrValue::String(&$event.client_id),
                MqttAttr::ConnackReason => AttrValue::UInt($event.connack_reason.into()),
                MqttAttr::Subscribe => AttrValue::VecString(&$event.subscribe),
                MqttAttr::SubackReason => AttrValue::VecUInt(
                    $event
                        .suback_reason
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                ),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlockListMqttFields {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub category: EventCategory,
}
impl fmt::Display for BlockListMqttFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} version={:?} client_id={:?} connack_reason={:?} subscribe={:?} suback_reason={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.protocol,
            self.version.to_string(),
            self.client_id,
            self.connack_reason.to_string(),
            self.subscribe.join(","),
            String::from_utf8_lossy(&self.suback_reason)
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlockListMqtt {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlockListMqtt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} last_time={:?} protocol={:?} version={:?} client_id={:?} connack_reason={:?} subscribe={:?} suback_reason={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.last_time.to_string(),
            self.protocol,
            self.version.to_string(),
            self.client_id,
            self.connack_reason.to_string(),
            self.subscribe.join(","),
            String::from_utf8_lossy(&self.suback_reason),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlockListMqtt {
    pub(super) fn new(time: DateTime<Utc>, fields: BlockListMqttFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            last_time: fields.last_time,
            protocol: fields.protocol,
            version: fields.version,
            client_id: fields.client_id,
            connack_reason: fields.connack_reason,
            subscribe: fields.subscribe,
            suback_reason: fields.suback_reason,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlockListMqtt {
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
        "block list mqtt"
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
        mqtt_target_attr!(self, raw_event_attr)
    }
}
