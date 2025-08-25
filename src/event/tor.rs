use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, HttpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::{
    common::{AttrValue, triage_scores_to_string},
    conn::BlocklistConnFields,
    http::{find_http_attr_by_kind, get_post_body},
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

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpEventFields {
    pub sensor: String,
    #[serde(with = "ts_nanoseconds")]
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl HttpEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?}",
            self.category.to_string(),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct TorConnection {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} end_time={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.end_time.to_rfc3339(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.orig_filenames.join(","),
            self.orig_mime_types.join(","),
            self.resp_filenames.join(","),
            self.resp_mime_types.join(","),
            get_post_body(&self.post_body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl TorConnection {
    pub(super) fn new(time: DateTime<Utc>, fields: &HttpEventFields) -> Self {
        TorConnection {
            time,
            sensor: fields.sensor.clone(),
            end_time: fields.end_time,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            orig_filenames: fields.orig_filenames.clone(),
            orig_mime_types: fields.orig_mime_types.clone(),
            resp_filenames: fields.resp_filenames.clone(),
            resp_mime_types: fields.resp_mime_types.clone(),
            post_body: fields.post_body.clone(),
            state: fields.state.clone(),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for TorConnection {
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
        "tor exit nodes"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct TorConnectionConn {
    pub sensor: String,
    pub time: DateTime<Utc>,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnectionConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} conn_state={:?} end_time={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            self.end_time.to_string(),
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

impl TorConnectionConn {
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

impl Match for TorConnectionConn {
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
        "tor exit nodes"
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use attrievent::attribute::{ConnAttr, RawEventAttrKind};
    use chrono::{TimeZone, Utc};

    use super::{Match, TorConnectionConn};
    use crate::event::{
        EventCategory, LearningMethod, MEDIUM, common::AttrValue, conn::BlocklistConnFields,
    };

    fn tor_connection_conn_fields() -> BlocklistConnFields {
        let end_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 1).unwrap();
        BlocklistConnFields {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.100".parse().unwrap(),
            src_port: 12345,
            dst_addr: "198.51.100.1".parse().unwrap(),
            dst_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            end_time: end_time.timestamp_nanos_opt().expect("valid time"),
            service: "https".to_string(),
            orig_bytes: 1024,
            resp_bytes: 2048,
            orig_pkts: 10,
            resp_pkts: 15,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2200,
            confidence: 0.95,
            category: EventCategory::CommandAndControl,
        }
    }

    #[test]
    fn tor_connection_conn_new() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let end_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 1).unwrap();
        let fields = tor_connection_conn_fields();

        let event = TorConnectionConn::new(time, fields);

        assert_eq!(event.time, time);
        assert_eq!(event.sensor, "test-sensor");
        assert_eq!(event.src_addr, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.src_port, 12345);
        assert_eq!(event.dst_addr, "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.proto, 6);
        assert_eq!(event.conn_state, "SF");
        assert_eq!(Utc.timestamp_nanos(event.end_time), end_time);
        assert_eq!(event.service, "https");
        assert_eq!(event.orig_bytes, 1024);
        assert_eq!(event.resp_bytes, 2048);
        assert_eq!(event.orig_pkts, 10);
        assert_eq!(event.resp_pkts, 15);
        assert_eq!(event.orig_l2_bytes, 1100);
        assert_eq!(event.resp_l2_bytes, 2200);
        assert!((event.confidence - 0.95).abs() < f32::EPSILON);
        assert_eq!(event.category, EventCategory::CommandAndControl);
        assert!(event.triage_scores.is_none());
    }

    #[test]
    fn tor_connection_conn_display() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        let display_output = format!("{event}");
        assert!(display_output.contains("sensor=\"test-sensor\""));
        assert!(display_output.contains("src_addr=\"192.168.1.100\""));
        assert!(display_output.contains("dst_addr=\"198.51.100.1\""));
        assert!(display_output.contains("conn_state=\"SF\""));
        assert!(display_output.contains("service=\"https\""));
    }

    #[test]
    fn tor_connection_conn_match_trait() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        assert_eq!(
            event.src_addrs(),
            &["192.168.1.100".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(event.src_port(), 12345);
        assert_eq!(
            event.dst_addrs(),
            &["198.51.100.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(event.dst_port(), 443);
        assert_eq!(event.proto(), 6);
        assert_eq!(event.category(), EventCategory::CommandAndControl);
        assert_eq!(event.level(), MEDIUM);
        assert_eq!(event.kind(), "tor exit nodes");
        assert_eq!(event.sensor(), "test-sensor");
        assert_eq!(event.confidence(), Some(0.95));
        assert!(matches!(
            event.learning_method(),
            LearningMethod::SemiSupervised
        ));
    }

    #[test]
    fn tor_connection_conn_find_attr_by_kind() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        // Test finding source address attribute
        let src_addr_attr = RawEventAttrKind::Conn(ConnAttr::SrcAddr);
        if let Some(AttrValue::Addr(addr)) = event.find_attr_by_kind(src_addr_attr) {
            assert_eq!(addr, "192.168.1.100".parse::<IpAddr>().unwrap());
        } else {
            panic!("Expected SrcAddr attribute");
        }

        // Test finding destination port attribute
        let dst_port_attr = RawEventAttrKind::Conn(ConnAttr::DstPort);
        if let Some(AttrValue::UInt(port)) = event.find_attr_by_kind(dst_port_attr) {
            assert_eq!(port, 443);
        } else {
            panic!("Expected DstPort attribute");
        }

        // Test finding protocol attribute
        let proto_attr = RawEventAttrKind::Conn(ConnAttr::Proto);
        if let Some(AttrValue::UInt(proto)) = event.find_attr_by_kind(proto_attr) {
            assert_eq!(proto, 6);
        } else {
            panic!("Expected Proto attribute");
        }

        // Test finding connection state attribute
        let conn_state_attr = RawEventAttrKind::Conn(ConnAttr::ConnState);
        if let Some(AttrValue::String(state)) = event.find_attr_by_kind(conn_state_attr) {
            assert_eq!(state, "SF");
        } else {
            panic!("Expected ConnState attribute");
        }

        // Test finding duration attribute
        let duration_attr = RawEventAttrKind::Conn(ConnAttr::Duration);
        if let Some(AttrValue::SInt(duration)) = event.find_attr_by_kind(duration_attr) {
            assert_eq!(duration, 1_000_000_000);
        } else {
            panic!("Expected Duration attribute");
        }

        // Test finding service attribute
        let service_attr = RawEventAttrKind::Conn(ConnAttr::Service);
        if let Some(AttrValue::String(service)) = event.find_attr_by_kind(service_attr) {
            assert_eq!(service, "https");
        } else {
            panic!("Expected Service attribute");
        }

        // Test finding byte count attributes
        let orig_bytes_attr = RawEventAttrKind::Conn(ConnAttr::OrigBytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(orig_bytes_attr) {
            assert_eq!(bytes, 1024);
        } else {
            panic!("Expected OrigBytes attribute");
        }

        let resp_bytes_attr = RawEventAttrKind::Conn(ConnAttr::RespBytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(resp_bytes_attr) {
            assert_eq!(bytes, 2048);
        } else {
            panic!("Expected RespBytes attribute");
        }

        // Test finding packet count attributes
        let orig_pkts_attr = RawEventAttrKind::Conn(ConnAttr::OrigPkts);
        if let Some(AttrValue::UInt(pkts)) = event.find_attr_by_kind(orig_pkts_attr) {
            assert_eq!(pkts, 10);
        } else {
            panic!("Expected OrigPkts attribute");
        }

        let resp_pkts_attr = RawEventAttrKind::Conn(ConnAttr::RespPkts);
        if let Some(AttrValue::UInt(pkts)) = event.find_attr_by_kind(resp_pkts_attr) {
            assert_eq!(pkts, 15);
        } else {
            panic!("Expected RespPkts attribute");
        }

        // Test finding L2 byte count attributes
        let orig_l2_bytes_attr = RawEventAttrKind::Conn(ConnAttr::OrigL2Bytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(orig_l2_bytes_attr) {
            assert_eq!(bytes, 1100);
        } else {
            panic!("Expected OrigL2Bytes attribute");
        }

        let resp_l2_bytes_attr = RawEventAttrKind::Conn(ConnAttr::RespL2Bytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(resp_l2_bytes_attr) {
            assert_eq!(bytes, 2200);
        } else {
            panic!("Expected RespL2Bytes attribute");
        }
    }
}
