use std::{
    fmt::{self, Formatter},
    net::IpAddr,
    num::NonZeroU8,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};
use attrievent::attribute::RawEventAttrKind;
use bincode::Options;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{
    eq_ip_country, EventCategory, EventFilter, FlowKind, LearningMethod, TrafficDirection,
};
use crate::{AttrCmpKind, Confidence, PacketAttr, Ti};

// TODO: Make new Match trait to support Windows Events

pub(super) trait Match {
    fn src_addr(&self) -> IpAddr;
    #[allow(dead_code)] // for future use
    fn src_port(&self) -> u16;
    fn dst_addr(&self) -> IpAddr;
    #[allow(dead_code)] // for future use
    fn dst_port(&self) -> u16;
    #[allow(dead_code)] // for future use
    fn proto(&self) -> u8;
    fn category(&self) -> EventCategory;
    fn level(&self) -> NonZeroU8;
    fn kind(&self) -> &str;
    fn sensor(&self) -> &str;
    fn confidence(&self) -> Option<f32>;
    fn to_attr_value(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue>;
    fn score_by_attr(&self, packet_attr: &[PacketAttr]) -> f64 {
        let mut total_score = 0.0;
        for attr in packet_attr {
            let Ok(raw_event_attr) =
                RawEventAttrKind::from_kind_and_attr_name(&attr.raw_event_kind, &attr.attr_name)
            else {
                continue;
            };
            let Some(target_attr_val) = self.to_attr_value(raw_event_attr) else {
                continue;
            };
            if process_attr_compare(target_attr_val, attr) {
                total_score += attr.weight.unwrap_or_default();
            }
        }
        (total_score * 100.0).trunc() / 100.0
    }

    /// Returns whether the event matches the filter and the triage scores. The triage scores are
    /// only returned if the event matches the filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter contains a country filter but the ip2location database is
    /// not available.
    fn matches(
        &self,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<(bool, Option<Vec<TriageScore>>)> {
        if !self.kind_matches(filter) {
            return Ok((false, None));
        }
        self.other_matches(filter, locator)
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        if let Some(kinds) = &filter.kinds {
            if kinds.iter().all(|k| k != self.kind()) {
                return false;
            }
        }

        true
    }

    /// Returns whether the event matches the filter (excluding `kinds`) and the triage scores. The
    /// triage scores are only returned if the event matches the filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter contains a country filter but the ip2location database is
    /// not available.
    #[allow(clippy::too_many_lines)]
    fn other_matches(
        &self,
        filter: &EventFilter,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
    ) -> Result<(bool, Option<Vec<TriageScore>>)> {
        if let Some(customers) = &filter.customers {
            if customers.iter().all(|customer| {
                !customer.contains(self.src_addr()) && !customer.contains(self.dst_addr())
            }) {
                return Ok((false, None));
            }
        }

        if let Some(endpoints) = &filter.endpoints {
            if endpoints.iter().all(|endpoint| match endpoint.direction {
                Some(TrafficDirection::From) => !endpoint.network.contains(self.src_addr()),
                Some(TrafficDirection::To) => !endpoint.network.contains(self.dst_addr()),
                None => {
                    !endpoint.network.contains(self.src_addr())
                        && !endpoint.network.contains(self.dst_addr())
                }
            }) {
                return Ok((false, None));
            }
        }

        if let Some(addr) = filter.source {
            if self.src_addr() != addr {
                return Ok((false, None));
            }
        }

        if let Some(addr) = filter.destination {
            if self.dst_addr() != addr {
                return Ok((false, None));
            }
        }

        if let Some((kinds, internal)) = &filter.directions {
            let internal_src = internal.iter().any(|net| net.contains(self.src_addr()));
            let internal_dst = internal.iter().any(|net| net.contains(self.dst_addr()));
            match (internal_src, internal_dst) {
                (true, true) => {
                    if !kinds.contains(&FlowKind::Internal) {
                        return Ok((false, None));
                    }
                }
                (true, false) => {
                    if !kinds.contains(&FlowKind::Outbound) {
                        return Ok((false, None));
                    }
                }
                (false, true) => {
                    if !kinds.contains(&FlowKind::Inbound) {
                        return Ok((false, None));
                    }
                }
                (false, false) => return Ok((false, None)),
            }
        }

        if let Some(countries) = &filter.countries {
            if let Some(locator) = locator {
                let Ok(mut locator) = locator.lock() else {
                    bail!("IP location database unavailable")
                };
                if countries.iter().all(|country| {
                    !eq_ip_country(&mut locator, self.src_addr(), *country)
                        && !eq_ip_country(&mut locator, self.dst_addr(), *country)
                }) {
                    return Ok((false, None));
                }
            } else {
                return Ok((false, None));
            }
        }

        if let Some(categories) = &filter.categories {
            if categories
                .iter()
                .all(|category| *category != self.category())
            {
                return Ok((false, None));
            }
        }

        if let Some(levels) = &filter.levels {
            if levels.iter().all(|level| *level != self.level()) {
                return Ok((false, None));
            }
        }

        if let Some(learning_methods) = &filter.learning_methods {
            let category = self.category();
            if learning_methods.iter().all(|learning_method| {
                let unsuper = matches!(*learning_method, LearningMethod::Unsupervised);
                let http = matches!(category, EventCategory::Reconnaissance);
                unsuper && !http || !unsuper && http
            }) {
                return Ok((false, None));
            }
        }

        if let Some(sensors) = &filter.sensors {
            if sensors.iter().all(|s| s != self.sensor()) {
                return Ok((false, None));
            }
        }

        if let Some(confidence) = &filter.confidence {
            if let Some(event_confidence) = self.confidence() {
                if event_confidence < *confidence {
                    return Ok((false, None));
                }
            }
        }

        if let Some(triage_policies) = &filter.triage_policies {
            if !triage_policies.is_empty() {
                let triage_scores = triage_policies
                    .iter()
                    .filter_map(|triage| {
                        let score = self.score_by_ti_db(&triage.ti_db)
                            + self.score_by_attr(&triage.packet_attr)
                            + self.score_by_confidence(&triage.confidence);
                        if triage.response.iter().any(|r| score >= r.minimum_score) {
                            Some(TriageScore {
                                policy_id: triage.id,
                                score,
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if triage_scores.is_empty() {
                    return Ok((false, None));
                }
                return Ok((true, Some(triage_scores)));
            }
        }

        Ok((true, None))
    }

    fn score_by_ti_db(&self, _ti_db: &[Ti]) -> f64 {
        // TODO: implement
        0.0
    }

    fn score_by_confidence(&self, confidence: &[Confidence]) -> f64 {
        confidence.iter().fold(0.0, |score, conf| {
            if conf.threat_category == self.category()
                && conf.threat_kind.to_lowercase() == self.kind().to_lowercase()
                && self.confidence().map_or(true, |c| {
                    c.to_f64().expect("safe: f32 -> f64") >= conf.confidence
                })
            {
                score + conf.weight.unwrap_or(1.0)
            } else {
                score
            }
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TriageScore {
    pub policy_id: u32,
    pub score: f64,
}

impl fmt::Display for TriageScore {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{:.2}", self.policy_id, self.score)
    }
}

pub fn triage_scores_to_string(v: Option<&Vec<TriageScore>>) -> String {
    if let Some(v) = v {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    } else {
        String::new()
    }
}

pub fn vector_to_string<T: ToString>(v: &[T]) -> String {
    if v.is_empty() {
        String::new()
    } else {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Converts a hardware address to a colon-separated string.
pub fn to_hardware_address(chaddr: &[u8]) -> String {
    let mut iter = chaddr.iter();
    let Some(first) = iter.next() else {
        return String::new();
    };
    iter.fold(
        {
            let mut addr = String::with_capacity(chaddr.len() * 3 - 1);
            addr.push_str(&format!("{first:02x}"));
            addr
        },
        |mut addr, byte| {
            addr.push(':');
            addr.push_str(&format!("{byte:02x}"));
            addr
        },
    )
}

pub enum AttrValue<'a> {
    Addr(IpAddr),
    Bool(bool),
    #[allow(dead_code)]
    Float(f64),
    SInt(i64),
    UInt(u64),
    String(&'a str),
    VecAddr(&'a [IpAddr]),
    #[allow(dead_code)]
    VecFloat(Vec<f64>),
    VecSInt(Vec<i64>),
    VecUInt(Vec<u64>),
    VecString(&'a [String]),
}

fn check_all_or_any<'a, T, F>(attr_val: &'a [T], packet_attr: &'a PacketAttr, compare_fn: F) -> bool
where
    F: Fn(&'a T, &'a PacketAttr) -> bool,
{
    match packet_attr.cmp_kind {
        AttrCmpKind::NotEqual | AttrCmpKind::NotContain => {
            attr_val.iter().all(|x| compare_fn(x, packet_attr))
        }
        _ => attr_val.iter().any(|x| compare_fn(x, packet_attr)),
    }
}

fn process_attr_compare(target_value: AttrValue, attr: &PacketAttr) -> bool {
    match target_value {
        AttrValue::Addr(ip_addr) => compare_addr_attribute(&ip_addr, attr),
        AttrValue::Bool(bool_val) => compare_bool_attribute(bool_val, attr),
        AttrValue::Float(float_val) => compare_number_attribute::<_, f64>(&float_val, attr),
        AttrValue::SInt(signed_int_val) => {
            compare_number_attribute::<_, i64>(&signed_int_val, attr)
        }
        AttrValue::UInt(unsigned_int_val) => {
            compare_number_attribute::<_, u64>(&unsigned_int_val, attr)
        }
        AttrValue::String(str_val) => compare_string_attribute(str_val, attr),
        AttrValue::VecAddr(vec_addr_val) => {
            check_all_or_any(vec_addr_val, attr, compare_addr_attribute)
        }
        AttrValue::VecFloat(vec_float_val) => {
            check_all_or_any(&vec_float_val, attr, compare_number_attribute::<_, f64>)
        }
        AttrValue::VecSInt(vec_sint_val) => {
            check_all_or_any(&vec_sint_val, attr, compare_number_attribute::<_, i64>)
        }
        AttrValue::VecUInt(vec_uint_val) => {
            check_all_or_any(&vec_uint_val, attr, compare_number_attribute::<_, u64>)
        }
        AttrValue::VecString(vec_str_val) => check_all_or_any(vec_str_val, attr, |val, attr| {
            compare_string_attribute(val.as_str(), attr)
        }),
    }
}

fn deserialize<'de, T>(value: &'de [u8]) -> Option<T>
where
    T: Deserialize<'de>,
{
    bincode::DefaultOptions::new().deserialize::<T>(value).ok()
}

fn check_second_value<'de, T, K>(kind: AttrCmpKind, value: Option<&'de Vec<u8>>) -> Option<T>
where
    T: TryFrom<K> + std::cmp::PartialOrd,
    K: Deserialize<'de>,
{
    match kind {
        AttrCmpKind::OpenRange
        | AttrCmpKind::CloseRange
        | AttrCmpKind::LeftOpenRange
        | AttrCmpKind::RightOpenRange
        | AttrCmpKind::NotOpenRange
        | AttrCmpKind::NotCloseRange
        | AttrCmpKind::NotLeftOpenRange
        | AttrCmpKind::NotRightOpenRange => {
            let value = value.as_ref()?;
            let de_second_value: K = deserialize(value)?;
            T::try_from(de_second_value).ok()
        }
        _ => None,
    }
}

fn compare_all_attr_cmp_kind<T>(
    cmp_kind: AttrCmpKind,
    attr_val: &T,
    first_val: &T,
    second_val: Option<T>,
) -> bool
where
    T: PartialOrd,
{
    match (cmp_kind, second_val) {
        (AttrCmpKind::Less, _) => attr_val < first_val,
        (AttrCmpKind::LessOrEqual, _) => attr_val <= first_val,
        (AttrCmpKind::Equal, _) => attr_val == first_val,
        (AttrCmpKind::NotEqual, _) => attr_val != first_val,
        (AttrCmpKind::Greater, _) => attr_val > first_val,
        (AttrCmpKind::GreaterOrEqual, _) => attr_val >= first_val,
        (AttrCmpKind::OpenRange, Some(second_val)) => {
            (first_val < attr_val) && (second_val > *attr_val)
        }
        (AttrCmpKind::CloseRange, Some(second_val)) => {
            (first_val <= attr_val) && (second_val >= *attr_val)
        }
        (AttrCmpKind::LeftOpenRange, Some(second_val)) => {
            (first_val < attr_val) && (second_val >= *attr_val)
        }
        (AttrCmpKind::RightOpenRange, Some(second_val)) => {
            (first_val <= attr_val) && (second_val > *attr_val)
        }
        (AttrCmpKind::NotOpenRange, Some(second_val)) => {
            !((first_val < attr_val) && (second_val > *attr_val))
        }
        (AttrCmpKind::NotCloseRange, Some(second_val)) => {
            !((first_val <= attr_val) && (second_val >= *attr_val))
        }
        (AttrCmpKind::NotLeftOpenRange, Some(second_val)) => {
            !((first_val < attr_val) && (second_val >= *attr_val))
        }
        (AttrCmpKind::NotRightOpenRange, Some(second_val)) => {
            !((first_val <= attr_val) && (second_val > *attr_val))
        }
        _ => false,
    }
}

fn compare_bool_attribute(attr_val: bool, packet_attr: &PacketAttr) -> bool {
    deserialize::<bool>(&packet_attr.first_value).is_some_and(|compare_val| {
        match packet_attr.cmp_kind {
            AttrCmpKind::Equal => attr_val == compare_val,
            AttrCmpKind::NotEqual => attr_val != compare_val,
            _ => false,
        }
    })
}

fn compare_string_attribute(attr_val: &str, packet_attr: &PacketAttr) -> bool {
    deserialize::<String>(&packet_attr.first_value).is_some_and(|compare_val| {
        let cmp_result = attr_val.contains(&compare_val);
        match packet_attr.cmp_kind {
            AttrCmpKind::Contain => cmp_result,
            AttrCmpKind::NotContain => !cmp_result,
            _ => false,
        }
    })
}

fn compare_addr_attribute(attr_val: &IpAddr, packet_attr: &PacketAttr) -> bool {
    if let Some(first_val) = deserialize::<IpAddr>(&packet_attr.first_value) {
        let second_val = packet_attr
            .second_value
            .as_ref()
            .and_then(|serde_val| deserialize::<IpAddr>(serde_val));
        return compare_all_attr_cmp_kind(packet_attr.cmp_kind, attr_val, &first_val, second_val);
    }
    false
}

fn compare_number_attribute<'de, T, K>(attr_val: &T, packet_attr: &'de PacketAttr) -> bool
where
    T: TryFrom<K> + PartialOrd,
    K: Deserialize<'de>,
{
    if let Some(first_val) = deserialize::<K>(&packet_attr.first_value) {
        if let Ok(first_val) = T::try_from(first_val) {
            let second_val =
                check_second_value::<T, K>(packet_attr.cmp_kind, packet_attr.second_value.as_ref());
            return compare_all_attr_cmp_kind(
                packet_attr.cmp_kind,
                attr_val,
                &first_val,
                second_val,
            );
        }
    };
    false
}

mod tests {

    use bincode::Options;
    use serde::Serialize;

    #[test]
    fn empty_byte_slice_to_colon_separated_string() {
        assert_eq!(super::to_hardware_address(&[]), "");
    }

    #[test]
    fn non_empty_byte_slice_to_colon_separated_string() {
        assert_eq!(
            super::to_hardware_address(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
            "12:34:56:78:9a:bc"
        );
    }

    #[allow(dead_code)]
    fn serialize<T>(v: &T) -> Option<Vec<u8>>
    where
        T: Serialize,
    {
        bincode::DefaultOptions::new().serialize(v).ok()
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn compare_attribute() {
        use std::net::{IpAddr, Ipv4Addr};

        use attrievent::attribute::{DhcpAttr, DnsAttr, HttpAttr, RawEventKind};
        use chrono::{TimeZone, Utc};

        use crate::{
            event::common::Match, AttrCmpKind, BlockListDhcp, BlockListDhcpFields, DgaFields,
            DnsCovertChannel, DnsEventFields, DomainGenerationAlgorithm, EventCategory, PacketAttr,
            ValueKind,
        };

        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();

        // Compare `Addr`, `String`, `UInt`, `VecString` type
        let fields = DgaFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)),
            dst_port: 80,
            proto: 6,
            duration: 1000,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referrer: "-".to_string(),
            version: "1.1".to_string(),
            user_agent: "browser".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "-".to_string(),
            username: "-".to_string(),
            password: "-".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "encoding type".to_string(),
            content_type: "content type".to_string(),
            cache_control: "no cache".to_string(),
            orig_filenames: vec!["a1".to_string(), "a2".to_string()],
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: vec!["b1".to_string(), "b2".to_string()],
            post_body: "12345678901234567890".to_string().into_bytes(),
            state: String::new(),
            confidence: 0.8,
            category: EventCategory::CommandAndControl,
        };

        let http_event = DomainGenerationAlgorithm::new(time, fields);
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::SrcAddr.to_string(),
                value_kind: ValueKind::IpAddr,
                cmp_kind: AttrCmpKind::CloseRange,
                first_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5))).unwrap(),
                second_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6))),
                weight: Some(0.1),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::Uri.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: serialize(&"path").unwrap(),
                second_value: None,
                weight: Some(0.2),
            },
        ];
        let score_result = http_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result, 0.3);

        let fail_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::DstPort.to_string(),
                value_kind: ValueKind::UInteger,
                cmp_kind: AttrCmpKind::OpenRange,
                first_value: serialize(&80_u64).unwrap(),
                second_value: serialize(&82_u64),
                weight: Some(0.1),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::RespMimeTypes.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::NotContain,
                first_value: serialize(&"b1").unwrap(),
                second_value: None,
                weight: Some(0.1),
            },
        ];
        let score_result = http_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result, 0.0);

        // Compare `Bool`, `SInt`, `VecSInt`
        let fields = DnsEventFields {
            sensor: "sensor".to_string(),
            session_end_time: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 53,
            proto: 17,
            query: "foo.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 5,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1, 3, 5, 7],
            confidence: 0.8,
            category: EventCategory::CommandAndControl,
        };
        let dns_event = DnsCovertChannel::new(time, fields);
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Dns,
                attr_name: DnsAttr::Rtt.to_string(),
                value_kind: ValueKind::Integer,
                cmp_kind: AttrCmpKind::Less,
                first_value: serialize(&6_i64).unwrap(),
                second_value: None,
                weight: Some(0.3),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Dns,
                attr_name: DnsAttr::Ttl.to_string(),
                value_kind: ValueKind::Integer,
                cmp_kind: AttrCmpKind::NotEqual,
                first_value: serialize(&9_i64).unwrap(),
                second_value: None,
                weight: Some(0.5),
            },
        ];
        let score_result = dns_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result, 0.8);

        let fail_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dns,
            attr_name: DnsAttr::AA.to_string(),
            value_kind: ValueKind::Bool,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&true).unwrap(),
            second_value: None,
            weight: Some(0.2),
        }];
        let score_result = dns_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result, 0.0);

        // Compare `VecAddr`, `VecUInt`
        let fields = BlockListDhcpFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 68,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 67,
            proto: 17,
            last_time: 100,
            msg_type: 1,
            ciaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
            yiaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)),
            siaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)),
            giaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)),
            subnet_mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            router: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
            ],
            domain_name_server: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            req_ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 100)),
            lease_time: 100,
            server_id: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            param_req_list: vec![2, 3, 4],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: "MSFT 5.0".to_string().into_bytes(),
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            category: EventCategory::InitialAccess,
        };

        let dhcp_event = BlockListDhcp::new(time, fields);
        let success_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dhcp,
            attr_name: DhcpAttr::Router.to_string(),
            value_kind: ValueKind::IpAddr,
            cmp_kind: AttrCmpKind::LeftOpenRange,
            first_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8))).unwrap(),
            second_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))),
            weight: Some(0.15),
        }];
        let score_result = dhcp_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result, 0.15);

        let fail_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dhcp,
            attr_name: DhcpAttr::ParamReqList.to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::RightOpenRange,
            first_value: serialize(&1_u64).unwrap(),
            second_value: serialize(&2_u64),
            weight: Some(0.35),
        }];
        let score_result = dhcp_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result, 0.0);
    }
}
