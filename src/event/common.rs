use std::{
    fmt::{self, Formatter},
    net::IpAddr,
    num::NonZeroU8,
};

use anyhow::Result;
use attrievent::attribute::RawEventAttrKind;
use bincode::Options;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{
    EventCategory, EventFilter, FlowKind, LearningMethod, TrafficDirection, eq_ip_country,
};
use crate::{AttrCmpKind, Confidence, PacketAttr, Ti, ValueKind};

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
    fn learning_method(&self) -> LearningMethod;
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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
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
                if countries.iter().all(|country| {
                    !eq_ip_country(locator, self.src_addr(), *country)
                        && !eq_ip_country(locator, self.dst_addr(), *country)
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
            if learning_methods
                .iter()
                .all(|learning_method| *learning_method != self.learning_method())
            {
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
                && self
                    .confidence()
                    .is_none_or(|c| c.to_f64().expect("safe: f32 -> f64") >= conf.confidence)
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
    VecRaw(&'a [u8]),
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
        AttrValue::VecRaw(vec_raw_val) => compare_vec_raw_attribute(vec_raw_val, attr),
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

fn compare_vec_raw_attribute(attr_val: &[u8], packet_attr: &PacketAttr) -> bool {
    match packet_attr.value_kind {
        ValueKind::String => {
            deserialize::<String>(&packet_attr.first_value).is_some_and(|compare_val| {
                compare_bytes(packet_attr.cmp_kind, attr_val, compare_val.as_bytes())
            })
        }
        ValueKind::Vector => {
            compare_bytes(packet_attr.cmp_kind, attr_val, &packet_attr.first_value)
        }
        _ => false,
    }
}

fn compare_bytes(cmp_kind: AttrCmpKind, target_val: &[u8], compare_val: &[u8]) -> bool {
    let cmp_result = memchr::memmem::find(target_val, compare_val);
    match cmp_kind {
        AttrCmpKind::Contain => cmp_result.is_some(),
        AttrCmpKind::NotContain => cmp_result.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        net::{IpAddr, Ipv4Addr},
    };

    use attrievent::attribute::{DhcpAttr, DnsAttr, HttpAttr, RawEventKind};
    use bincode::Options;
    use chrono::{TimeZone, Utc};
    use serde::Serialize;

    use crate::{
        AttrCmpKind, BlockListBootp, BlockListBootpFields, BlockListConn, BlockListConnFields,
        BlockListDceRpc, BlockListDceRpcFields, BlockListDhcp, BlockListDhcpFields, BlockListDns,
        BlockListDnsFields, BlockListFtp, BlockListHttp, BlockListHttpFields, BlockListKerberos,
        BlockListKerberosFields, BlockListLdap, BlockListMqtt, BlockListMqttFields, BlockListNfs,
        BlockListNfsFields, BlockListNtlm, BlockListNtlmFields, BlockListRdp, BlockListRdpFields,
        BlockListSmb, BlockListSmbFields, BlockListSmtp, BlockListSmtpFields, BlockListSsh,
        BlockListSshFields, BlockListTls, BlockListTlsFields, CryptocurrencyMiningPool,
        CryptocurrencyMiningPoolFields, DgaFields, DnsCovertChannel, DnsEventFields,
        DomainGenerationAlgorithm, Event, EventCategory, EventFilter, ExternalDdos,
        ExternalDdosFields, ExtraThreat, FtpBruteForce, FtpBruteForceFields, FtpEventFields,
        FtpPlainText, HttpEventFields, HttpThreat, HttpThreatFields, LdapBruteForce,
        LdapBruteForceFields, LdapEventFields, LdapPlainText, LearningMethod, LockyRansomware,
        MultiHostPortScan, MultiHostPortScanFields, NetworkThreat, NonBrowser, PacketAttr,
        PortScan, PortScanFields, RdpBruteForce, RdpBruteForceFields, RecordType,
        RepeatedHttpSessions, RepeatedHttpSessionsFields, SuspiciousTlsTraffic, TorConnection,
        ValueKind, WindowsThreat, event::common::Match,
    };

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

    #[test]
    fn learning_method_match_on_semi_supervised_events() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();
        let mut semi_supervised_events = Vec::new();

        let dns_event = Event::DnsCovertChannel(DnsCovertChannel::new(time, dns_event_fields()));
        semi_supervised_events.push(dns_event);

        let port_scan_event = Event::PortScan(PortScan::new(time, &port_scan_fields()));
        semi_supervised_events.push(port_scan_event);

        let multi_host_port_scan_event =
            Event::MultiHostPortScan(MultiHostPortScan::new(time, &multi_host_port_scan_fields()));
        semi_supervised_events.push(multi_host_port_scan_event);

        let external_ddos_event =
            Event::ExternalDdos(ExternalDdos::new(time, &external_ddos_fields()));
        semi_supervised_events.push(external_ddos_event);

        let locky_ransomware_event =
            Event::LockyRansomware(LockyRansomware::new(time, dns_event_fields()));
        semi_supervised_events.push(locky_ransomware_event);

        let crypto_mining_pool_event = Event::CryptocurrencyMiningPool(
            CryptocurrencyMiningPool::new(time, crypto_miining_pool_fields()),
        );
        semi_supervised_events.push(crypto_mining_pool_event);

        let ftp_brute_force_event =
            Event::FtpBruteForce(FtpBruteForce::new(time, &ftp_brute_force_fields()));
        semi_supervised_events.push(ftp_brute_force_event);

        let ftp_plain_text_event = Event::FtpPlainText(FtpPlainText::new(time, ftp_event_fields()));
        semi_supervised_events.push(ftp_plain_text_event);

        let repeated_http_sessions_event = Event::RepeatedHttpSessions(RepeatedHttpSessions::new(
            time,
            &repeated_http_sessions_fiedls(),
        ));
        semi_supervised_events.push(repeated_http_sessions_event);

        let dga_event =
            Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, dga_fields()));
        semi_supervised_events.push(dga_event);

        let non_browser_event = Event::NonBrowser(NonBrowser::new(time, &http_event_fields()));
        semi_supervised_events.push(non_browser_event);

        let ldap_brute_force_event =
            Event::LdapBruteForce(LdapBruteForce::new(time, &ldap_brute_force_fields()));
        semi_supervised_events.push(ldap_brute_force_event);

        let ldap_plain_text_event =
            Event::LdapPlainText(LdapPlainText::new(time, ldap_event_fields()));
        semi_supervised_events.push(ldap_plain_text_event);

        let rdp_brute_force_event =
            Event::RdpBruteForce(RdpBruteForce::new(time, &rdp_brute_force_fields()));
        semi_supervised_events.push(rdp_brute_force_event);

        let suspicious_tls_traffic_event =
            Event::SuspiciousTlsTraffic(SuspiciousTlsTraffic::new(time, block_list_tls_fields()));
        semi_supervised_events.push(suspicious_tls_traffic_event);

        let tor_connection_event =
            Event::TorConnection(TorConnection::new(time, &http_event_fields()));
        semi_supervised_events.push(tor_connection_event);

        let block_list_bootp_event = Event::BlockList(RecordType::Bootp(BlockListBootp::new(
            time,
            block_list_bootp_fields(),
        )));
        semi_supervised_events.push(block_list_bootp_event);

        let block_list_conn_event = Event::BlockList(RecordType::Conn(BlockListConn::new(
            time,
            block_list_conn_fields(),
        )));
        semi_supervised_events.push(block_list_conn_event);

        let block_list_dcerpc_event = Event::BlockList(RecordType::DceRpc(BlockListDceRpc::new(
            time,
            block_list_dcerpc_fields(),
        )));
        semi_supervised_events.push(block_list_dcerpc_event);

        let block_list_dhcp_event = Event::BlockList(RecordType::Dhcp(BlockListDhcp::new(
            time,
            block_list_dhcp_fields(),
        )));
        semi_supervised_events.push(block_list_dhcp_event);

        let block_list_dns_event = Event::BlockList(RecordType::Dns(BlockListDns::new(
            time,
            block_list_dns_fields(),
        )));
        semi_supervised_events.push(block_list_dns_event);

        let block_list_ftp_event =
            Event::BlockList(RecordType::Ftp(BlockListFtp::new(time, ftp_event_fields())));
        semi_supervised_events.push(block_list_ftp_event);

        let block_list_http_event = Event::BlockList(RecordType::Http(BlockListHttp::new(
            time,
            block_list_http_fields(),
        )));
        semi_supervised_events.push(block_list_http_event);

        let block_list_kerberos_event = Event::BlockList(RecordType::Kerberos(
            BlockListKerberos::new(time, block_list_kerberos_fields()),
        ));
        semi_supervised_events.push(block_list_kerberos_event);

        let block_list_ldap_event = Event::BlockList(RecordType::Ldap(BlockListLdap::new(
            time,
            ldap_event_fields(),
        )));
        semi_supervised_events.push(block_list_ldap_event);

        let block_list_mqtt_event = Event::BlockList(RecordType::Mqtt(BlockListMqtt::new(
            time,
            block_list_mqtt_fields(),
        )));
        semi_supervised_events.push(block_list_mqtt_event);

        let block_list_nfs_event = Event::BlockList(RecordType::Nfs(BlockListNfs::new(
            time,
            block_list_nfs_fields(),
        )));
        semi_supervised_events.push(block_list_nfs_event);

        let block_list_ntlm_event = Event::BlockList(RecordType::Ntlm(BlockListNtlm::new(
            time,
            block_list_ntlm_fields(),
        )));
        semi_supervised_events.push(block_list_ntlm_event);

        let block_list_rdp_event = Event::BlockList(RecordType::Rdp(BlockListRdp::new(
            time,
            block_list_rdp_fields(),
        )));
        semi_supervised_events.push(block_list_rdp_event);

        let block_list_smb_event = Event::BlockList(RecordType::Smb(BlockListSmb::new(
            time,
            block_list_smb_fields(),
        )));
        semi_supervised_events.push(block_list_smb_event);

        let block_list_smtp_event = Event::BlockList(RecordType::Smtp(BlockListSmtp::new(
            time,
            block_list_smtp_fields(),
        )));
        semi_supervised_events.push(block_list_smtp_event);

        let block_list_ssh_event = Event::BlockList(RecordType::Ssh(BlockListSsh::new(
            time,
            block_list_ssh_fields(),
        )));
        semi_supervised_events.push(block_list_ssh_event);

        let block_list_tls_event = Event::BlockList(RecordType::Tls(BlockListTls::new(
            time,
            block_list_tls_fields(),
        )));
        semi_supervised_events.push(block_list_tls_event);

        let mut filter = event_filter();

        // Semi-supervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::SemiSupervised]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );

        // Unsupervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::Unsupervised]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| !event.matches(None, &filter).unwrap().0)
        );

        // All event filtering
        filter.learning_methods = Some(vec![
            LearningMethod::SemiSupervised,
            LearningMethod::Unsupervised,
        ]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );
    }

    #[test]
    fn learning_method_match_on_unsupervised_events() {
        let mut unsupervised_events = Vec::new();

        let http_threat_event = Event::HttpThreat(HttpThreat::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            http_threat_fields(),
        ));
        unsupervised_events.push(http_threat_event);

        let extra_threat_event = Event::ExtraThreat(extra_threat());
        unsupervised_events.push(extra_threat_event);

        let network_threat_event = Event::NetworkThreat(network_threat());
        unsupervised_events.push(network_threat_event);

        let windows_threat_event = Event::WindowsThreat(windows_threat());
        unsupervised_events.push(windows_threat_event);

        let mut filter = event_filter();

        // Semi-supervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::SemiSupervised]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| !event.matches(None, &filter).unwrap().0)
        );

        // Unsupervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::Unsupervised]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );

        // All event filtering
        filter.learning_methods = Some(vec![
            LearningMethod::SemiSupervised,
            LearningMethod::Unsupervised,
        ]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );
    }

    #[test]
    fn compare_attribute() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();

        // Compare `Addr`, `String`, `UInt`, `VecString`, `VecRaw(compare to String)` type
        let http_event = DomainGenerationAlgorithm::new(time, dga_fields());
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::SrcAddr.to_string(),
                value_kind: ValueKind::IpAddr,
                cmp_kind: AttrCmpKind::CloseRange,
                first_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).unwrap(),
                second_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
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
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::PostBody.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: serialize(&"12345678901234567890").unwrap(),
                second_value: None,
                weight: Some(0.3),
            },
        ];
        let score_result = http_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.6), Some(Ordering::Equal));

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
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));

        // Compare `Bool`, `SInt`, `VecSInt` type
        let dns_event = DnsCovertChannel::new(time, dns_event_fields());
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
        assert_eq!(score_result.partial_cmp(&0.8), Some(Ordering::Equal));

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
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));

        // Compare `VecAddr`, `VecUInt`, `VecRaw(compare to Vector)` type
        let dhcp_event = BlockListDhcp::new(time, block_list_dhcp_fields());
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Dhcp,
                attr_name: DhcpAttr::Router.to_string(),
                value_kind: ValueKind::IpAddr,
                cmp_kind: AttrCmpKind::LeftOpenRange,
                first_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0))).unwrap(),
                second_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                weight: Some(0.15),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Dhcp,
                attr_name: DhcpAttr::ClientId.to_string(),
                value_kind: ValueKind::Vector,
                cmp_kind: AttrCmpKind::Contain,
                first_value: vec![7, 8, 9],
                second_value: None,
                weight: Some(0.2),
            },
        ];
        let score_result = dhcp_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.35), Some(Ordering::Equal));

        let fail_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dhcp,
            attr_name: DhcpAttr::ParamReqList.to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::RightOpenRange,
            first_value: serialize(&0_u64).unwrap(),
            second_value: serialize(&1_u64),
            weight: Some(0.35),
        }];
        let score_result = dhcp_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));
    }

    fn serialize<T>(v: &T) -> Option<Vec<u8>>
    where
        T: Serialize,
    {
        bincode::DefaultOptions::new().serialize(v).ok()
    }

    fn event_filter() -> EventFilter {
        EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: None,
            destination: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: None,
            learning_methods: None,
            sensors: None,
            confidence: None,
            triage_policies: None,
        }
    }

    fn block_list_bootp_fields() -> BlockListBootpFields {
        BlockListBootpFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 68,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 67,
            proto: 17,
            last_time: 100,
            op: 1,
            htype: 2,
            hops: 1,
            xid: 1,
            ciaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
            yiaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)),
            siaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)),
            giaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "server_name".to_string(),
            file: "boot_file_name".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_conn_fields() -> BlockListConnFields {
        BlockListConnFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            conn_state: "SAF".to_string(),
            duration: 1000,
            service: "http".to_string(),
            orig_bytes: 100,
            orig_pkts: 1,
            resp_bytes: 100,
            resp_pkts: 1,
            orig_l2_bytes: 122,
            resp_l2_bytes: 122,
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_dcerpc_fields() -> BlockListDceRpcFields {
        BlockListDceRpcFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 135,
            proto: 6,
            last_time: 100,
            rtt: 1,
            named_pipe: "svcctl".to_string(),
            endpoint: "epmapper".to_string(),
            operation: "bind".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_dhcp_fields() -> BlockListDhcpFields {
        BlockListDhcpFields {
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
            subnet_mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            router: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            domain_name_server: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            req_ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 100)),
            lease_time: 100,
            server_id: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            param_req_list: vec![1, 2, 3],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: "MSFT 5.0".as_bytes().to_vec(),
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_dns_fields() -> BlockListDnsFields {
        BlockListDnsFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 53,
            proto: 17,
            last_time: 100,
            query: "foo.com".to_string(),
            answer: vec!["10.10.10.10".to_string(), "20.20.20.20".to_string()],
            trans_id: 123,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: true,
            ttl: vec![120; 5],
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_http_fields() -> BlockListHttpFields {
        BlockListHttpFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            last_time: 600,
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
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_kerberos_fields() -> BlockListKerberosFields {
        BlockListKerberosFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 88,
            proto: 17,
            last_time: 100,
            client_time: 100,
            server_time: 101,
            error_code: 0,
            client_realm: "EXAMPLE.COM".to_string(),
            cname_type: 1,
            client_name: vec!["user1".to_string()],
            realm: "EXAMPLE.COM".to_string(),
            sname_type: 1,
            service_name: vec!["krbtgt/EXAMPLE.COM".to_string()],
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_mqtt_fields() -> BlockListMqttFields {
        BlockListMqttFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 1883,
            proto: 6,
            last_time: 100,
            protocol: "mqtt".to_string(),
            version: 211,
            client_id: "client1".to_string(),
            connack_reason: 0,
            subscribe: vec!["topic".to_string()],
            suback_reason: "error".to_string().into_bytes(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_nfs_fields() -> BlockListNfsFields {
        BlockListNfsFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 2049,
            proto: 6,
            last_time: 100,
            read_files: vec!["/etc/passwd".to_string()],
            write_files: vec!["/etc/shadow".to_string()],
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_ntlm_fields() -> BlockListNtlmFields {
        BlockListNtlmFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 445,
            proto: 6,
            last_time: 100,
            protocol: "ntlm".to_string(),
            username: "user1".to_string(),
            hostname: "host1".to_string(),
            domainname: "domain1".to_string(),
            success: "true".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_rdp_fields() -> BlockListRdpFields {
        BlockListRdpFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 3389,
            proto: 6,
            last_time: 100,
            cookie: "cookie".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_smb_fields() -> BlockListSmbFields {
        BlockListSmbFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 445,
            proto: 6,
            last_time: 100,
            command: 1,
            path: "path".to_string(),
            service: "service".to_string(),
            file_name: "file_name".to_string(),
            file_size: 100,
            resource_type: 1,
            fid: 1,
            create_time: 100,
            access_time: 200,
            write_time: 300,
            change_time: 400,
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_smtp_fields() -> BlockListSmtpFields {
        BlockListSmtpFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 25,
            proto: 6,
            last_time: 100,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
            state: "state".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_ssh_fields() -> BlockListSshFields {
        BlockListSshFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 22,
            proto: 6,
            last_time: 100,
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            hassh_algorithms: "hassh_algorithms".to_string(),
            hassh: "hassh".to_string(),
            hassh_server_algorithms: "hassh_server_algorithms".to_string(),
            hassh_server: "hassh_server".to_string(),
            client_shka: "client_shka".to_string(),
            server_shka: "server_shka".to_string(),
            category: EventCategory::InitialAccess,
        }
    }

    fn block_list_tls_fields() -> BlockListTlsFields {
        BlockListTlsFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 443,
            proto: 6,
            last_time: 100,
            server_name: "server".to_string(),
            alpn_protocol: "alpn".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: vec![1, 2, 3],
            client_extensions: vec![4, 5, 6],
            cipher: 1,
            extensions: vec![7, 8, 9],
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "country".to_string(),
            subject_org_name: "org".to_string(),
            subject_common_name: "common".to_string(),
            validity_not_before: 100,
            validity_not_after: 200,
            subject_alt_name: "alt".to_string(),
            issuer_country: "country".to_string(),
            issuer_org_name: "org".to_string(),
            issuer_org_unit_name: "unit".to_string(),
            issuer_common_name: "common".to_string(),
            category: EventCategory::InitialAccess,
            last_alert: 1,
        }
    }

    fn ldap_event_fields() -> LdapEventFields {
        LdapEventFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 389,
            proto: 6,
            last_time: 100,
            message_id: 1,
            version: 3,
            opcode: vec!["bind".to_string()],
            result: vec!["success".to_string()],
            diagnostic_message: vec!["msg".to_string()],
            object: vec!["object".to_string()],
            argument: vec!["argument".to_string()],
            category: EventCategory::LateralMovement,
        }
    }

    fn ftp_event_fields() -> FtpEventFields {
        FtpEventFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 21,
            proto: 6,
            last_time: 100,
            user: "user1".to_string(),
            password: "password".to_string(),
            command: "ls".to_string(),
            reply_code: "200".to_string(),
            reply_msg: "OK".to_string(),
            data_passive: false,
            data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            sensor: "collector1".to_string(),
            data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            data_resp_port: 10001,
            file: "/etc/passwd".to_string(),
            file_size: 5000,
            file_id: "123".to_string(),
            category: EventCategory::LateralMovement,
        }
    }

    fn port_scan_fields() -> PortScanFields {
        PortScanFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_ports: vec![80, 443, 8000, 8080, 8888, 8443, 9000, 9001, 9002],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            proto: 6,
            category: EventCategory::Reconnaissance,
        }
    }

    fn multi_host_port_scan_fields() -> MultiHostPortScanFields {
        MultiHostPortScanFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            dst_port: 80,
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            proto: 6,
            category: EventCategory::Reconnaissance,
        }
    }

    fn external_ddos_fields() -> ExternalDdosFields {
        ExternalDdosFields {
            src_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            proto: 6,
            category: EventCategory::Impact,
        }
    }

    fn crypto_miining_pool_fields() -> CryptocurrencyMiningPoolFields {
        CryptocurrencyMiningPoolFields {
            sensor: "sensro".to_string(),
            session_end_time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 53,
            proto: 17,
            query: "foo.com".to_string(),
            answer: vec!["10.10.10.10".to_string(), "20.20.20.20".to_string()],
            trans_id: 123,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: true,
            ttl: vec![120; 5],
            coins: vec!["bitcoin".to_string(), "monero".to_string()],
            category: EventCategory::CommandAndControl,
        }
    }

    fn ftp_brute_force_fields() -> FtpBruteForceFields {
        FtpBruteForceFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 21,
            proto: 6,
            user_list: vec!["user1".to_string(), "user_2".to_string()],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            is_internal: true,
            category: EventCategory::CredentialAccess,
        }
    }

    fn repeated_http_sessions_fiedls() -> RepeatedHttpSessionsFields {
        RepeatedHttpSessionsFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 443,
            proto: 6,
            category: EventCategory::Exfiltration,
        }
    }

    fn dga_fields() -> DgaFields {
        DgaFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            duration: 1000,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
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
        }
    }

    fn http_event_fields() -> HttpEventFields {
        HttpEventFields {
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            session_end_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 10, 10).unwrap(),
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
            category: EventCategory::CommandAndControl,
        }
    }

    fn ldap_brute_force_fields() -> LdapBruteForceFields {
        LdapBruteForceFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 389,
            proto: 6,
            user_pw_list: vec![
                ("user1".to_string(), "pw1".to_string()),
                ("user_2".to_string(), "pw2".to_string()),
            ],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            category: EventCategory::CredentialAccess,
        }
    }

    fn rdp_brute_force_fields() -> RdpBruteForceFields {
        RdpBruteForceFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 10, 2).unwrap(),
            proto: 6,
            category: EventCategory::Discovery,
        }
    }

    fn dns_event_fields() -> DnsEventFields {
        DnsEventFields {
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
        }
    }

    fn network_threat() -> NetworkThreat {
        NetworkThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            service: "http".to_string(),
            last_time: 100,
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            triage_scores: None,
            category: EventCategory::Reconnaissance,
        }
    }

    fn extra_threat() -> ExtraThreat {
        ExtraThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            service: "service".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            category: EventCategory::Reconnaissance,
            triage_scores: None,
        }
    }

    fn windows_threat() -> WindowsThreat {
        WindowsThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            service: "notepad".to_string(),
            agent_name: "win64".to_string(),
            agent_id: "e7e2386a-5485-4da9-b388-b3e50ee7cbb0".to_string(),
            process_guid: "{bac98147-6b03-64d4-8200-000000000700}".to_string(),
            process_id: 2972,
            image: r"C:\Users\vboxuser\Desktop\mal_bazaar\ransomware\918504.exe".to_string(),
            user: r"WIN64\vboxuser".to_string(),
            content: r#"cmd /c "vssadmin.exe Delete Shadows /all /quiet""#.to_string(),
            db_name: "db".to_string(),
            rule_id: 100,
            matched_to: "match".to_string(),
            cluster_id: Some(900),
            attack_kind: "Ransomware_Alcatraz".to_string(),
            confidence: 0.9,
            triage_scores: None,
            category: EventCategory::Impact,
        }
    }

    fn http_threat_fields() -> HttpThreatFields {
        HttpThreatFields {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            duration: 1000,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
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
            db_name: "db".to_string(),
            rule_id: 12000,
            cluster_id: Some(1111),
            matched_to: "match".to_string(),
            attack_kind: "attack".to_string(),
            confidence: 0.8,
            category: EventCategory::Reconnaissance,
        }
    }
}
