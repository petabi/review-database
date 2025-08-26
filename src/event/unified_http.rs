use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{HttpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{
    EventCategory, EventFilter, LOW, LearningMethod, MEDIUM, TriageScore,
    common::{AttrValue, Match, triage_scores_to_string},
    http::{find_http_attr_by_kind, get_post_body},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpEventBase {
    pub sensor: String,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum HttpEventVariant {
    Basic {
        #[serde(with = "ts_nanoseconds")]
        session_end_time: DateTime<Utc>,
    },
    Threat {
        end_time: i64,
        db_name: String,
        rule_id: u32,
        matched_to: String,
        cluster_id: Option<usize>,
        attack_kind: String,
    },
    Dga {
        duration: i64,
    },
    Blocklist {
        end_time: i64,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnifiedHttpEventFields {
    #[serde(flatten)]
    pub base: HttpEventBase,
    #[serde(flatten)]
    pub variant: HttpEventVariant,
}

#[derive(Deserialize, Serialize)]
pub struct UnifiedHttpEvent {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    #[serde(flatten)]
    pub fields: UnifiedHttpEventFields,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl UnifiedHttpEventFields {
    #[must_use]
    pub fn new_basic(base: HttpEventBase, session_end_time: DateTime<Utc>) -> Self {
        Self {
            base,
            variant: HttpEventVariant::Basic { session_end_time },
        }
    }

    #[must_use]
    pub fn new_threat(
        base: HttpEventBase,
        end_time: i64,
        db_name: String,
        rule_id: u32,
        matched_to: String,
        cluster_id: Option<usize>,
        attack_kind: String,
    ) -> Self {
        Self {
            base,
            variant: HttpEventVariant::Threat {
                end_time,
                db_name,
                rule_id,
                matched_to,
                cluster_id,
                attack_kind,
            },
        }
    }

    #[must_use]
    pub fn new_dga(base: HttpEventBase, duration: i64) -> Self {
        Self {
            base,
            variant: HttpEventVariant::Dga { duration },
        }
    }

    #[must_use]
    pub fn new_blocklist(base: HttpEventBase, end_time: i64) -> Self {
        Self {
            base,
            variant: HttpEventVariant::Blocklist { end_time },
        }
    }

    #[must_use]
    pub fn event_kind(&self) -> &'static str {
        match &self.variant {
            HttpEventVariant::Basic { .. } => "non browser",
            HttpEventVariant::Threat { .. } => "http threat",
            HttpEventVariant::Dga { .. } => "dga",
            HttpEventVariant::Blocklist { .. } => "blocklist http",
        }
    }

    #[must_use]
    pub fn confidence(&self) -> Option<f32> {
        match &self.variant {
            HttpEventVariant::Basic { .. } => None,
            _ => Some(self.base.confidence),
        }
    }

    #[must_use]
    pub fn level(&self) -> NonZeroU8 {
        match &self.variant {
            HttpEventVariant::Threat { .. } | HttpEventVariant::Dga { .. } => LOW,
            HttpEventVariant::Basic { .. } | HttpEventVariant::Blocklist { .. } => MEDIUM,
        }
    }

    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let base_format = format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?} confidence={:?}",
            self.base.category.to_string(),
            self.base.sensor,
            self.base.src_addr.to_string(),
            self.base.src_port.to_string(),
            self.base.dst_addr.to_string(),
            self.base.dst_port.to_string(),
            self.base.proto.to_string(),
            self.base.method,
            self.base.host,
            self.base.uri,
            self.base.referer,
            self.base.version,
            self.base.user_agent,
            self.base.request_len.to_string(),
            self.base.response_len.to_string(),
            self.base.status_code.to_string(),
            self.base.status_msg,
            self.base.username,
            self.base.password,
            self.base.cookie,
            self.base.content_encoding,
            self.base.content_type,
            self.base.cache_control,
            self.base.orig_filenames.join(","),
            self.base.orig_mime_types.join(","),
            self.base.resp_filenames.join(","),
            self.base.resp_mime_types.join(","),
            get_post_body(&self.base.post_body),
            self.base.state,
            self.base.confidence.to_string(),
        );

        match &self.variant {
            HttpEventVariant::Basic { session_end_time } => {
                format!(
                    "{} session_end_time={:?}",
                    base_format,
                    session_end_time.to_rfc3339()
                )
            }
            HttpEventVariant::Threat {
                end_time,
                db_name,
                rule_id,
                matched_to,
                cluster_id,
                attack_kind,
            } => {
                format!(
                    "{} end_time={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?}",
                    base_format,
                    chrono::DateTime::from_timestamp_nanos(*end_time).to_rfc3339(),
                    db_name,
                    rule_id.to_string(),
                    matched_to,
                    cluster_id.map_or("-".to_string(), |s| s.to_string()),
                    attack_kind,
                )
            }
            HttpEventVariant::Dga { duration } => {
                format!("{} duration={:?}", base_format, duration.to_string())
            }
            HttpEventVariant::Blocklist { end_time } => {
                format!("{} end_time={:?}", base_format, end_time.to_string())
            }
        }
    }
}

impl fmt::Display for UnifiedHttpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base_fields = format!(
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} orig_filenames={:?} orig_mime_types={:?} resp_filenames={:?} resp_mime_types={:?} post_body={:?} state={:?}",
            self.fields.base.sensor,
            self.fields.base.src_addr.to_string(),
            self.fields.base.src_port.to_string(),
            self.fields.base.dst_addr.to_string(),
            self.fields.base.dst_port.to_string(),
            self.fields.base.proto.to_string(),
            self.fields.base.method,
            self.fields.base.host,
            self.fields.base.uri,
            self.fields.base.referer,
            self.fields.base.version,
            self.fields.base.user_agent,
            self.fields.base.request_len.to_string(),
            self.fields.base.response_len.to_string(),
            self.fields.base.status_code.to_string(),
            self.fields.base.status_msg,
            self.fields.base.username,
            self.fields.base.password,
            self.fields.base.cookie,
            self.fields.base.content_encoding,
            self.fields.base.content_type,
            self.fields.base.cache_control,
            self.fields.base.orig_filenames.join(","),
            self.fields.base.orig_mime_types.join(","),
            self.fields.base.resp_filenames.join(","),
            self.fields.base.resp_mime_types.join(","),
            get_post_body(&self.fields.base.post_body),
            self.fields.base.state,
        );

        let variant_fields = match &self.fields.variant {
            HttpEventVariant::Basic { session_end_time } => {
                format!(" session_end_time={:?}", session_end_time.to_rfc3339())
            }
            HttpEventVariant::Threat {
                end_time,
                db_name,
                rule_id,
                matched_to,
                cluster_id,
                attack_kind,
            } => {
                format!(
                    " duration={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
                    end_time.to_string(),
                    db_name,
                    rule_id.to_string(),
                    matched_to,
                    cluster_id.map_or("-".to_string(), |s| s.to_string()),
                    attack_kind,
                    self.fields.base.confidence.to_string(),
                )
            }
            HttpEventVariant::Dga { duration } => {
                format!(
                    " duration={:?} confidence={:?}",
                    duration.to_string(),
                    self.fields.base.confidence.to_string()
                )
            }
            HttpEventVariant::Blocklist { end_time } => {
                format!(" end_time={:?}", end_time.to_string())
            }
        };

        write!(
            f,
            "{}{} triage_scores={:?}",
            base_fields,
            variant_fields,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl UnifiedHttpEvent {
    #[cfg(test)]
    pub(super) fn new(time: DateTime<Utc>, fields: UnifiedHttpEventFields) -> Self {
        Self {
            time,
            fields,
            triage_scores: None,
        }
    }
}

impl Match for UnifiedHttpEvent {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.fields.base.src_addr)
    }

    fn src_port(&self) -> u16 {
        self.fields.base.src_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.fields.base.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        self.fields.base.dst_port
    }

    fn proto(&self) -> u8 {
        self.fields.base.proto
    }

    fn category(&self) -> EventCategory {
        self.fields.base.category
    }

    fn level(&self) -> NonZeroU8 {
        self.fields.level()
    }

    fn kind(&self) -> &'static str {
        self.fields.event_kind()
    }

    fn sensor(&self) -> &str {
        self.fields.base.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        self.fields.confidence()
    }

    fn learning_method(&self) -> LearningMethod {
        match &self.fields.variant {
            HttpEventVariant::Threat { .. } => LearningMethod::Unsupervised,
            HttpEventVariant::Basic { .. }
            | HttpEventVariant::Dga { .. }
            | HttpEventVariant::Blocklist { .. } => LearningMethod::SemiSupervised,
        }
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_http_attr_by_kind!(self.fields.base, raw_event_attr)
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        // Only HttpThreat has special kind matching logic
        if let HttpEventVariant::Threat { attack_kind, .. } = &self.fields.variant
            && let Some(kinds) = &filter.kinds
        {
            use aho_corasick::AhoCorasickBuilder;

            let patterns = attack_kind
                .split_whitespace()
                .filter(|s| s.chars().any(char::is_alphanumeric))
                .map(ToString::to_string)
                .collect::<Vec<String>>();
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(patterns)
                .expect("automatic build should not fail");
            if kinds.iter().all(|kind| {
                let words = kind
                    .split_whitespace()
                    .filter(|s| s.chars().any(char::is_alphanumeric))
                    .map(ToString::to_string)
                    .collect::<Vec<String>>();
                !words.iter().all(|w| ac.is_match(w))
            }) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::{TimeZone, Utc};

    use super::*;

    fn sample_http_base() -> HttpEventBase {
        HttpEventBase {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.1".parse().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse().unwrap(),
            dst_port: 443,
            proto: 6,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/test".to_string(),
            referer: "https://example.com".to_string(),
            version: "HTTP/1.1".to_string(),
            user_agent: "test-agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            cookie: "session=123".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            orig_filenames: vec!["file1.txt".to_string()],
            orig_mime_types: vec!["text/plain".to_string()],
            resp_filenames: vec!["response.html".to_string()],
            resp_mime_types: vec!["text/html".to_string()],
            post_body: b"test data".to_vec(),
            state: "active".to_string(),
            confidence: 0.8,
            category: EventCategory::CommandAndControl,
        }
    }

    #[test]
    fn test_unified_http_event_basic() {
        let base = sample_http_base();
        let session_end_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let fields = UnifiedHttpEventFields::new_basic(base, session_end_time);
        let event = UnifiedHttpEvent::new(session_end_time, fields);

        assert_eq!(event.fields.base.sensor, "test-sensor");
        assert_eq!(event.fields.event_kind(), "non browser");
        assert_eq!(event.fields.confidence(), None);
        assert_eq!(event.fields.level(), MEDIUM);

        // Test syslog output
        let syslog = event.fields.syslog_rfc5424();
        assert!(syslog.contains("sensor=\"test-sensor\""));
        assert!(syslog.contains("session_end_time="));
    }

    #[test]
    fn test_unified_http_event_threat() {
        let base = sample_http_base();
        let fields = UnifiedHttpEventFields::new_threat(
            base,
            1_640_995_200_000_000_000_i64, // 2022-01-01 00:00:00 UTC in nanoseconds
            "test-db".to_string(),
            123,
            "malware".to_string(),
            Some(42),
            "trojan".to_string(),
        );
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = UnifiedHttpEvent::new(time, fields);

        assert_eq!(event.fields.event_kind(), "http threat");
        assert_eq!(event.fields.confidence(), Some(0.8));
        assert_eq!(event.fields.level(), LOW);

        if let HttpEventVariant::Threat {
            db_name,
            rule_id,
            attack_kind,
            ..
        } = &event.fields.variant
        {
            assert_eq!(db_name, "test-db");
            assert_eq!(*rule_id, 123);
            assert_eq!(attack_kind, "trojan");
        } else {
            panic!("Expected Threat variant");
        }
    }

    #[test]
    fn test_unified_http_event_dga() {
        let base = sample_http_base();
        let fields = UnifiedHttpEventFields::new_dga(base, 5000);
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = UnifiedHttpEvent::new(time, fields);

        assert_eq!(event.fields.event_kind(), "dga");
        assert_eq!(event.fields.confidence(), Some(0.8));
        assert_eq!(event.fields.level(), LOW);

        if let HttpEventVariant::Dga { duration } = &event.fields.variant {
            assert_eq!(*duration, 5000);
        } else {
            panic!("Expected Dga variant");
        }
    }

    #[test]
    fn test_unified_http_event_blocklist() {
        let base = sample_http_base();
        let fields = UnifiedHttpEventFields::new_blocklist(base, 1_640_995_200_000_000_000_i64);
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = UnifiedHttpEvent::new(time, fields);

        assert_eq!(event.fields.event_kind(), "blocklist http");
        assert_eq!(event.fields.confidence(), Some(0.8));
        assert_eq!(event.fields.level(), MEDIUM);
    }

    #[test]
    fn test_match_trait_implementation() {
        let base = sample_http_base();
        let session_end_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let fields = UnifiedHttpEventFields::new_basic(base, session_end_time);
        let event = UnifiedHttpEvent::new(session_end_time, fields);

        assert_eq!(
            event.src_addrs(),
            &["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(event.src_port(), 8080);
        assert_eq!(event.dst_addrs(), &["10.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(event.dst_port(), 443);
        assert_eq!(event.proto(), 6);
        assert_eq!(event.category(), EventCategory::CommandAndControl);
        assert_eq!(event.sensor(), "test-sensor");
        assert_eq!(event.learning_method(), LearningMethod::SemiSupervised);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let base = sample_http_base();
        let fields = UnifiedHttpEventFields::new_threat(
            base,
            1_640_995_200_000_000_000_i64,
            "test-db".to_string(),
            123,
            "malware".to_string(),
            Some(42),
            "trojan".to_string(),
        );
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let original = UnifiedHttpEvent::new(time, fields);

        let serialized = serde_json::to_string(&original).expect("serialization failed");
        let deserialized: UnifiedHttpEvent =
            serde_json::from_str(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.time, original.time);
        assert_eq!(deserialized.fields.base.sensor, original.fields.base.sensor);
        assert_eq!(
            deserialized.fields.event_kind(),
            original.fields.event_kind()
        );
    }
}
