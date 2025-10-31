use std::{fmt, net::IpAddr, num::NonZeroU8};

use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

#[derive(Serialize, Deserialize)]
pub struct BlocklistRadiusFields {
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
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistRadiusFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} id={:?} code={:?} resp_code={:?} auth={:?} resp_auth={:?} user_name={:?} user_passwd={:?} chap_passwd={:?} nas_ip={:?} nas_port={:?} state={:?} nas_id={:?} nas_port_type={:?} message={:?} confidence={:?}",
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
            self.id.to_string(),
            self.code.to_string(),
            self.resp_code.to_string(),
            self.auth,
            self.resp_auth,
            String::from_utf8_lossy(&self.user_name),
            String::from_utf8_lossy(&self.user_passwd),
            String::from_utf8_lossy(&self.chap_passwd),
            self.nas_ip.to_string(),
            self.nas_port.to_string(),
            String::from_utf8_lossy(&self.state),
            String::from_utf8_lossy(&self.nas_id),
            self.nas_port_type.to_string(),
            self.message,
            self.confidence.to_string(),
        )
    }
}

pub struct BlocklistRadius {
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
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistRadius {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start_time_str = DateTime::from_timestamp_nanos(self.start_time).to_rfc3339();
        let end_time_str = DateTime::from_timestamp_nanos(self.end_time).to_rfc3339();

        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} id={:?} code={:?} resp_code={:?} auth={:?} resp_auth={:?} user_name={:?} user_passwd={:?} chap_passwd={:?} nas_ip={:?} nas_port={:?} state={:?} nas_id={:?} nas_port_type={:?} message={:?} triage_scores={:?}",
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
            self.id.to_string(),
            self.code.to_string(),
            self.resp_code.to_string(),
            self.auth,
            self.resp_auth,
            String::from_utf8_lossy(&self.user_name),
            String::from_utf8_lossy(&self.user_passwd),
            String::from_utf8_lossy(&self.chap_passwd),
            self.nas_ip.to_string(),
            self.nas_port.to_string(),
            String::from_utf8_lossy(&self.state),
            String::from_utf8_lossy(&self.nas_id),
            self.nas_port_type.to_string(),
            self.message,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistRadius {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistRadiusFields) -> Self {
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
            id: fields.id,
            code: fields.code,
            resp_code: fields.resp_code,
            auth: fields.auth,
            resp_auth: fields.resp_auth,
            user_name: fields.user_name,
            user_passwd: fields.user_passwd,
            chap_passwd: fields.chap_passwd,
            nas_ip: fields.nas_ip,
            nas_port: fields.nas_port,
            state: fields.state,
            nas_id: fields.nas_id,
            nas_port_type: fields.nas_port_type,
            message: fields.message,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistRadius {
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
        "blocklist radius"
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

    fn find_attr_by_kind(
        &self,
        _raw_event_attr: attrievent::attribute::RawEventAttrKind,
    ) -> Option<AttrValue<'_>> {
        // TODO: Implement when RawEventAttrKind::Radius is available
        None
    }
}
