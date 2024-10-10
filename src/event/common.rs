use std::{
    fmt::{self, Formatter},
    net::IpAddr,
    num::NonZeroU8,
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};
use bincode::Options;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{
    eq_ip_country, EventCategory, EventFilter, FlowKind, LearningMethod, TrafficDirection,
    TriagePolicy,
};
use crate::{AttrCmpKind, PacketAttr};

// TODO: Make new Match trait to support Windows Events

pub(super) trait Match<T: FromStr> {
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
    fn source(&self) -> &str;
    fn confidence(&self) -> Option<f32>;
    fn target_attribute(&self, proto_attr: T) -> Option<AttrValue>;
    fn score_by_packet_attr(&self, triage: &TriagePolicy) -> f64 {
        let mut attr_total_score = 0.0;
        for attr in &triage.packet_attr {
            let Ok(proto_attr) = T::from_str(&attr.attr_name) else {
                continue;
            };
            let Some(target_attr_val) = self.target_attribute(proto_attr) else {
                continue;
            };
            if process_attr_compare(target_attr_val, attr) {
                attr_total_score += attr.weight.unwrap(); //weight always exist.
            }
        }
        attr_total_score
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
            if sensors.iter().all(|s| s != self.source()) {
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
                        let score = self.score_by_ti_db(triage)
                            + self.score_by_packet_attr(triage)
                            + self.score_by_confidence(triage);
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

    fn score_by_ti_db(&self, _triage: &TriagePolicy) -> f64 {
        // TODO: implement
        0.0
    }

    fn score_by_confidence(&self, triage: &TriagePolicy) -> f64 {
        triage.confidence.iter().fold(0.0, |score, conf| {
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

pub fn triage_scores_to_string(v: &Option<Vec<TriageScore>>) -> String {
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

pub enum AttrValue {
    Addr(IpAddr),
    Bool(bool),
    Float(f64),
    SInt(i64),
    UInt(u64),
    String(String),
    VecAddr(Vec<IpAddr>),
    VecFloat(Vec<f64>),
    VecSInt(Vec<i64>),
    VecUInt(Vec<u64>),
    VecString(Vec<String>),
}

fn process_attr_compare(target_value: AttrValue, attr: &PacketAttr) -> bool {
    match target_value {
        AttrValue::Addr(ip_addr) => process_attr_compare_addr(ip_addr, attr),
        AttrValue::Bool(bool_val) => process_attr_compare_bool(bool_val, attr),
        AttrValue::Float(float_val) => process_attr_compare_number::<_, f64>(&float_val, attr),
        AttrValue::SInt(signed_int_val) => {
            process_attr_compare_number::<_, i64>(&signed_int_val, attr)
        }
        AttrValue::UInt(unsigned_int_val) => {
            process_attr_compare_number::<_, u64>(&unsigned_int_val, attr)
        }
        AttrValue::String(str_val) => process_attr_compare_string(&str_val, attr),
        AttrValue::VecAddr(vec_addr_val) => vec_addr_val
            .iter()
            .any(|addr| process_attr_compare_addr(*addr, attr)),
        AttrValue::VecFloat(vec_float_val) => vec_float_val
            .iter()
            .any(|float| process_attr_compare_number::<_, f64>(float, attr)),
        AttrValue::VecSInt(vec_int_val) => vec_int_val
            .iter()
            .any(|int| process_attr_compare_number::<_, i64>(int, attr)),
        AttrValue::VecUInt(vec_int_val) => vec_int_val
            .iter()
            .any(|int| process_attr_compare_number::<_, u64>(int, attr)),
        AttrValue::VecString(vec_str_val) => vec_str_val
            .iter()
            .any(|str| process_attr_compare_string(str, attr)),
    }
}

fn deserialize<'de, T>(value: &'de [u8]) -> Option<T>
where
    T: Deserialize<'de>,
{
    bincode::DefaultOptions::new().deserialize::<T>(value).ok()
}

fn check_second_value<'de, T, K>(kind: AttrCmpKind, value: &'de Option<Vec<u8>>) -> Option<T>
where
    T: TryFrom<K> + std::cmp::PartialOrd,
    K: Deserialize<'de>,
{
    if matches!(
        kind,
        AttrCmpKind::CloseRange
            | AttrCmpKind::LeftOpenRange
            | AttrCmpKind::RightOpenRange
            | AttrCmpKind::NotOpenRange
            | AttrCmpKind::NotCloseRange
            | AttrCmpKind::NotLeftOpenRange
            | AttrCmpKind::NotRightOpenRange
    ) {
        let value_result = value.as_ref()?;
        let de_second_value = deserialize::<K>(value_result)?;
        let convert_second_value = T::try_from(de_second_value).ok()?;
        Some(convert_second_value)
    } else {
        None
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

fn process_attr_compare_bool(attr_val: bool, packet_attr: &PacketAttr) -> bool {
    deserialize::<bool>(&packet_attr.first_value).is_some_and(|compare_val| {
        match packet_attr.cmp_kind {
            AttrCmpKind::Equal => attr_val == compare_val,
            AttrCmpKind::NotEqual => attr_val != compare_val,
            _ => false,
        }
    })
}

fn process_attr_compare_string(attr_val: &str, packet_attr: &PacketAttr) -> bool {
    deserialize::<String>(&packet_attr.first_value).is_some_and(|compare_val| {
        let cmp_result = attr_val.contains(&compare_val);
        match packet_attr.cmp_kind {
            AttrCmpKind::Contain => cmp_result,
            AttrCmpKind::NotContain => !cmp_result,
            _ => false,
        }
    })
}

fn process_attr_compare_addr(attr_val: IpAddr, packet_attr: &PacketAttr) -> bool {
    if let Some(first_val) = deserialize::<IpAddr>(&packet_attr.first_value) {
        let second_val = if let Some(serde_val) = &packet_attr.second_value {
            deserialize::<IpAddr>(serde_val)
        } else {
            None
        };
        return compare_all_attr_cmp_kind(packet_attr.cmp_kind, &attr_val, &first_val, second_val);
    }
    false
}

fn process_attr_compare_number<'de, T, K>(attr_val: &T, packet_attr: &'de PacketAttr) -> bool
where
    T: TryFrom<K> + PartialOrd,
    K: Deserialize<'de>,
{
    if let Some(first_val) = deserialize::<K>(&packet_attr.first_value) {
        if let Ok(first_val) = T::try_from(first_val) {
            let second_val =
                check_second_value::<T, K>(packet_attr.cmp_kind, &packet_attr.second_value);
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
}
