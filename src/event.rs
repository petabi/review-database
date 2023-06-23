#![allow(clippy::too_many_lines)]
mod common;
mod conn;
mod dns;
mod ftp;
mod http;
mod ldap;
mod rdp;
mod tor;

use self::{common::Match, http::RepeatedHttpSessionsFields, rdp::RdpBruteForceFields};
pub use self::{
    common::TriageScore,
    conn::{
        ExternalDDos, ExternalDDosFields, MultiHostPortScan, MultiHostPortScanFields, PortScan,
        PortScanFields,
    },
    dns::{DnsCovertChannel, DnsEventFields},
    ftp::{FtpBruteForce, FtpBruteForceFields, FtpPlainText, FtpPlainTextFields},
    http::{
        DgaFields, DomainGenerationAlgorithm, HttpThreat, HttpThreatFields, NonBrowser,
        NonBrowserFields, RepeatedHttpSessions,
    },
    ldap::{LdapBruteForce, LdapBruteForceFields, LdapPlainText, LdapPlainTextFields},
    rdp::RdpBruteForce,
    tor::{TorConnection, TorConnectionFields},
};
use super::{
    types::{Customer, Endpoint, EventCategory, FromKeyValue, HostNetworkGroup, TriagePolicy},
    Indexable,
};
use aho_corasick::AhoCorasickBuilder;
use anyhow::{bail, Context, Result};
use bincode::Options;
use chrono::{serde::ts_nanoseconds, DateTime, TimeZone, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{thread_rng, RngCore};
pub use rocksdb::Direction;
use rocksdb::{DBIteratorWithThreadMode, IteratorMode};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    mem::size_of,
    net::IpAddr,
    num::NonZeroU8,
    sync::{Arc, Mutex, MutexGuard},
};

// event levels (currently unused ones commented out)
// const VERY_LOW: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(1) };
const LOW: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(2) };
const MEDIUM: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(3) };
// const HIGH: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(4) };
// const VERY_HIGH: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(5) };

// event kind
const DNS_COVERT_CHANNEL: &str = "DNS Covert Channel";
const HTTP_THREAT: &str = "HTTP Threat";
const RDP_BRUTE_FORCE: &str = "RDP Brute Force";
const REPEATED_HTTP_SESSIONS: &str = "Repeated HTTP Sessions";
const TOR_CONNECTION: &str = "Tor Connection";
const DOMAIN_GENERATION_ALGIRITHM: &str = "Domain Generation Algorithm";
const FTP_BRUTE_FORCE: &str = "FTP Brute Force";
const FTP_PLAIN_TEXT: &str = "FTP Plain text";
const PORT_SCAN: &str = "Port Scan";
const MULTI_HOST_PORT_SCAN: &str = "Multi Host Port Scan";
const EXTERNAL_DDOS: &str = "External Ddos";
const NON_BROWSER: &str = "Non Browser";
const LDAP_BRUTE_FORCE: &str = "LDAP Brute Force";
const LDAP_PLAIN_TEXT: &str = "LDAP Plain Text";

pub enum Event {
    /// DNS requests and responses that convey unusual host names.
    DnsCovertChannel(DnsCovertChannel),

    /// HTTP-related threats.
    HttpThreat(HttpThreat),

    /// Brute force attacks against RDP, attempting to guess passwords.
    RdpBruteForce(RdpBruteForce),

    /// Multiple HTTP sessions with the same source and destination that occur within a short time.
    /// This is a sign of a possible unauthorized communication channel.
    RepeatedHttpSessions(RepeatedHttpSessions),

    /// An HTTP connection to a Tor exit node.
    TorConnection(TorConnection),

    /// DGA (Domain Generation Algorithm) generated hostname in HTTP request message
    DomainGenerationAlgorithm(DomainGenerationAlgorithm),

    /// Brute force attacks against FTP.
    FtpBruteForce(FtpBruteForce),

    /// Plain text password is used for the FTP connection.
    FtpPlainText(FtpPlainText),

    /// Large number of connection attempts are made to multiple ports
    /// on the same destination from the same source.
    PortScan(PortScan),

    /// Specific host inside attempts to connect to a specific port on multiple host inside.
    MultiHostPortScan(MultiHostPortScan),

    /// multiple internal host attempt a DDOS attack against a specific external host.
    ExternalDDos(ExternalDDos),

    /// Non-browser user agent detected in HTTP request message.
    NonBrowser(NonBrowser),

    /// Brute force attacks against LDAP.
    LdapBruteForce(LdapBruteForce),

    /// Plain text password is used for the LDAP connection.
    LdapPlainText(LdapPlainText),
}

impl Event {
    /// Returns whether the event matches the given filter. If the event matches, returns the
    /// triage score for the event.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter contains a country filter but the ip2location database is
    /// not available.
    pub fn matches(
        &self,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<(bool, Option<Vec<TriageScore>>)> {
        match self {
            Event::DnsCovertChannel(event) => event.matches(locator, filter),
            Event::HttpThreat(event) => event.matches(locator, filter),
            Event::RdpBruteForce(event) => event.matches(locator, filter),
            Event::RepeatedHttpSessions(event) => event.matches(locator, filter),
            Event::TorConnection(event) => event.matches(locator, filter),
            Event::DomainGenerationAlgorithm(event) => event.matches(locator, filter),
            Event::FtpBruteForce(event) => event.matches(locator, filter),
            Event::FtpPlainText(event) => event.matches(locator, filter),
            Event::PortScan(event) => event.matches(locator, filter),
            Event::MultiHostPortScan(event) => event.matches(locator, filter),
            Event::ExternalDDos(event) => event.matches(locator, filter),
            Event::NonBrowser(event) => event.matches(locator, filter),
            Event::LdapBruteForce(event) => event.matches(locator, filter),
            Event::LdapPlainText(event) => event.matches(locator, filter),
        }
    }

    /// Counts the number of events per country.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    #[allow(clippy::needless_pass_by_value)] // function prototype must be the same as other `count_*` functions.
    pub fn count_country(
        &self,
        counter: &mut HashMap<String, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    let src_country = locator.as_ref().map_or_else(
                        || "ZZ".to_string(),
                        |mutex| {
                            if let Ok(mut locator) = mutex.lock() {
                                find_ip_country(&mut locator, event.src_addr)
                            } else {
                                "ZZ".to_string()
                            }
                        },
                    );
                    let entry = counter.entry(src_country).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    let src_country = locator.as_ref().map_or_else(
                        || "ZZ".to_string(),
                        |mutex| {
                            if let Ok(mut locator) = mutex.lock() {
                                find_ip_country(&mut locator, event.src_addr)
                            } else {
                                "ZZ".to_string()
                            }
                        },
                    );
                    let entry = counter.entry(src_country).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    let dst_country = locator.as_ref().map_or_else(
                        || "ZZ".to_string(),
                        |mutex| {
                            if let Ok(mut locator) = mutex.lock() {
                                find_ip_country(&mut locator, event.dst_addr)
                            } else {
                                "ZZ".to_string()
                            }
                        },
                    );
                    let entry = counter.entry(dst_country).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator.clone(), filter)?.0 {
                    common_count_country(&locator, counter, event.src_addr, event.dst_addr);
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per category.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_category(
        &self,
        counter: &mut HashMap<EventCategory, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CommandAndControl).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Reconnaissance).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Discovery).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Exfiltration).or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CommandAndControl).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CommandAndControl).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CredentialAccess).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::LateralMovement).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Reconnaissance).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Reconnaissance).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::Impact).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CommandAndControl).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::CredentialAccess).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EventCategory::LateralMovement).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    common_count_ip_address(counter, event.src_addr, event.dst_addr);
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per IP address pair.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr), usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(_event) => {}
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(_event) => {}
            Event::ExternalDDos(_event) => {}
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry((event.src_addr, event.dst_addr)).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per IP address and event kind.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair_and_kind(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr, &'static str), usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, DNS_COVERT_CHANNEL))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, HTTP_THREAT))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(_event) => {}
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, REPEATED_HTTP_SESSIONS))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, TOR_CONNECTION))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, DOMAIN_GENERATION_ALGIRITHM))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, FTP_BRUTE_FORCE))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, FTP_PLAIN_TEXT))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, PORT_SCAN))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(_event) => {}
            Event::ExternalDDos(_event) => {}
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, NON_BROWSER))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, LDAP_BRUTE_FORCE))
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry((event.src_addr, event.dst_addr, LDAP_PLAIN_TEXT))
                        .or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per source IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_src_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(_event) => {}
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.src_addr).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per destination IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_dst_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(_event) => {}
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(_event) => {}
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.dst_addr).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per event kind.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_kind(
        &self,
        counter: &mut HashMap<String, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(DNS_COVERT_CHANNEL.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(event.attack_kind.clone()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(RDP_BRUTE_FORCE.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry(REPEATED_HTTP_SESSIONS.to_string())
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(TOR_CONNECTION.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter
                        .entry(DOMAIN_GENERATION_ALGIRITHM.to_string())
                        .or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(FTP_BRUTE_FORCE.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(FTP_PLAIN_TEXT.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(PORT_SCAN.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MULTI_HOST_PORT_SCAN.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(EXTERNAL_DDOS.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(NON_BROWSER.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(LDAP_BRUTE_FORCE.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(LDAP_PLAIN_TEXT.to_string()).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per level.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_level(
        &self,
        counter: &mut HashMap<NonZeroU8, usize>,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(LOW).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    let entry = counter.entry(MEDIUM).or_insert(0);
                    *entry += 1;
                }
            }
        }
        Ok(())
    }

    /// Counts the number of events per network.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_network(
        &self,
        counter: &mut HashMap<u32, usize>,
        networks: &[Network],
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<()> {
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::ExternalDDos(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    if let Some(id) = find_network(event.src_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                    if let Some(id) = find_network(event.dst_addr, networks) {
                        let entry = counter.entry(id).or_insert(0);
                        *entry += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// Sets the triage scores of the event.
    pub fn set_triage_scores(&mut self, triage_scores: Vec<TriageScore>) {
        match self {
            Event::DnsCovertChannel(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::HttpThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::RdpBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::RepeatedHttpSessions(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::TorConnection(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::DomainGenerationAlgorithm(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::FtpBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::FtpPlainText(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::PortScan(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::MultiHostPortScan(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::ExternalDDos(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::NonBrowser(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::LdapBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::LdapPlainText(event) => {
                event.triage_scores = Some(triage_scores);
            }
        }
    }
}

fn find_network(ip: IpAddr, networks: &[Network]) -> Option<u32> {
    for net in networks.iter() {
        if net.contains(ip) {
            return Some(net.id);
        }
    }
    None
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, PartialEq, ToPrimitive)]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    Log,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDDos,
}

/// Machine Learning Method.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

#[allow(clippy::module_name_repetitions)]
pub struct EventFilter {
    customers: Option<Vec<Customer>>,
    endpoints: Option<Vec<Endpoint>>,
    directions: Option<(Vec<FlowKind>, Vec<HostNetworkGroup>)>,
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    countries: Option<Vec<[u8; 2]>>,
    categories: Option<Vec<EventCategory>>,
    levels: Option<Vec<NonZeroU8>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    sensors: Option<Vec<String>>,
    confidence: Option<f32>,
    triage_policies: Option<Vec<TriagePolicy>>,
}

impl EventFilter {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        customers: Option<Vec<Customer>>,
        endpoints: Option<Vec<Endpoint>>,
        directions: Option<(Vec<FlowKind>, Vec<HostNetworkGroup>)>,
        source: Option<IpAddr>,
        destination: Option<IpAddr>,
        countries: Option<Vec<[u8; 2]>>,
        categories: Option<Vec<EventCategory>>,
        levels: Option<Vec<NonZeroU8>>,
        kinds: Option<Vec<String>>,
        learning_methods: Option<Vec<LearningMethod>>,
        sensors: Option<Vec<String>>,
        confidence: Option<f32>,
        triage_policies: Option<Vec<TriagePolicy>>,
    ) -> Self {
        Self {
            customers,
            endpoints,
            directions,
            source,
            destination,
            countries,
            categories,
            levels,
            kinds,
            learning_methods,
            sensors,
            confidence,
            triage_policies,
        }
    }

    #[must_use]
    pub fn has_country(&self) -> bool {
        self.countries.is_some()
    }

    pub fn moderate_kinds(&mut self) {
        if let Some(kinds) = self.kinds.as_mut() {
            moderate_kinds_by(kinds, &["dns", "covert", "channel"], "dns covert channel");
            moderate_kinds_by(
                kinds,
                &["http", "covert", "channel"],
                "repeated http sessions",
            );
            moderate_kinds_by(kinds, &["rdp", "brute", "force"], "rdp brute force");
            moderate_kinds_by(kinds, &["tor", "connection"], "tor exit nodes");
            moderate_kinds_by(kinds, &["domain", "generation", "algorithm"], "dga");
            moderate_kinds_by(kinds, &["ftp", "brute", "force"], "ftp brute force");
            moderate_kinds_by(kinds, &["ftp", "plain", "text"], "ftp plain text");
            moderate_kinds_by(kinds, &["ldap", "brute", "force"], "ldap brute force");
            moderate_kinds_by(kinds, &["ldap", "plain", "text"], "ldap plain text");
            moderate_kinds_by(
                kinds,
                &["multi", "host", "port", "scan"],
                "multi host port scan",
            );
            moderate_kinds_by(kinds, &["external", "ddos"], "external ddos");
            moderate_kinds_by(kinds, &["port", "scan"], "port scan");
            moderate_kinds_by(kinds, &["non", "browser"], "non browser");
        }
    }
}

fn moderate_kinds_by(kinds: &mut Vec<String>, patterns: &[&str], full_name: &str) {
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns);
    if kinds.iter().any(|kind| {
        let words = kind
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        words.iter().all(|w| ac.is_match(w))
    }) {
        kinds.push(full_name.to_string());
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct EventMessage {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}

impl fmt::Display for EventMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{},", self.time.to_rfc3339())?;
        match self.kind {
            EventKind::DnsCovertChannel => {
                if let Ok(fields) = bincode::deserialize::<DnsEventFields>(&self.fields) {
                    write!(f, "DnsCovertChannel,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::HttpThreat => {
                if let Ok(fields) = bincode::deserialize::<HttpThreatFields>(&self.fields) {
                    write!(f, "HttpThreat,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::RdpBruteForce => {
                if let Ok(fields) = bincode::deserialize::<RdpBruteForceFields>(&self.fields) {
                    write!(f, "RdpBruteForce,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::RepeatedHttpSessions => {
                if let Ok(fields) = bincode::deserialize::<RepeatedHttpSessionsFields>(&self.fields)
                {
                    write!(f, "RepeatedHttpSessions,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::TorConnection => {
                if let Ok(fields) = bincode::deserialize::<TorConnectionFields>(&self.fields) {
                    write!(f, "TorConnection,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::DomainGenerationAlgorithm => {
                if let Ok(fields) = bincode::deserialize::<DgaFields>(&self.fields) {
                    write!(f, "DomainGenerationAlgorithm,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::FtpBruteForce => {
                if let Ok(fields) = bincode::deserialize::<FtpBruteForceFields>(&self.fields) {
                    write!(f, "FtpBruteForce,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::FtpPlainText => {
                if let Ok(fields) = bincode::deserialize::<FtpPlainTextFields>(&self.fields) {
                    write!(f, "FtpPlainText,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::PortScan => {
                if let Ok(fields) = bincode::deserialize::<PortScanFields>(&self.fields) {
                    write!(f, "PortScan,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::MultiHostPortScan => {
                if let Ok(fields) = bincode::deserialize::<MultiHostPortScanFields>(&self.fields) {
                    write!(f, "MultiHostPortScan,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::NonBrowser => {
                if let Ok(fields) = bincode::deserialize::<NonBrowserFields>(&self.fields) {
                    write!(f, "NonBrowser,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::LdapBruteForce => {
                if let Ok(fields) = bincode::deserialize::<LdapBruteForceFields>(&self.fields) {
                    write!(f, "LdapBruteForce,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::LdapPlainText => {
                if let Ok(fields) = bincode::deserialize::<LdapPlainTextFields>(&self.fields) {
                    write!(f, "LdapPlainText,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::ExternalDDos => {
                if let Ok(fields) = bincode::deserialize::<ExternalDDosFields>(&self.fields) {
                    write!(f, "ExternalDDos,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::Log => Ok(()),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventDb<'a> {
    inner: &'a rocksdb::OptimisticTransactionDB,
}

impl<'a> EventDb<'a> {
    #[must_use]
    pub fn new(inner: &'a rocksdb::OptimisticTransactionDB) -> EventDb {
        Self { inner }
    }

    /// Creates an iterator over key-value pairs, starting from `key`.
    #[must_use]
    pub fn iter_from(&self, key: i128, direction: Direction) -> EventIterator {
        let iter = self
            .inner
            .iterator(IteratorMode::From(&key.to_be_bytes(), direction));
        EventIterator { inner: iter }
    }

    /// Creates an iterator over key-value pairs for the entire events.
    #[must_use]
    pub fn iter_forward(&self) -> EventIterator {
        let iter = self.inner.iterator(IteratorMode::Start);
        EventIterator { inner: iter }
    }

    /// Creates an raw iterator over key-value pairs for the entire events.
    #[must_use]
    pub(crate) fn raw_iter_forward(
        &self,
    ) -> DBIteratorWithThreadMode<rocksdb::OptimisticTransactionDB> {
        self.inner.iterator(IteratorMode::Start)
    }

    /// Stores a new event into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn put(&self, event: &EventMessage) -> Result<i128> {
        let mut key = i128::from(event.time.timestamp_nanos()) << 64
            | event.kind.to_i128().expect("should not exceed i128::MAX") << 32;
        loop {
            let txn = self.inner.transaction();
            if txn
                .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
                .context("cannot read from event database")?
                .is_some()
            {
                let start = i128::from(thread_rng().next_u32());
                key |= start;
                #[allow(clippy::cast_possible_wrap)] // bit pattern
                while txn
                    .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
                    .context("cannot read from event database")?
                    .is_some()
                {
                    let next = (key + 1) & 0xffff_ffff;
                    if next == start {
                        bail!("too many events with the same timestamp");
                    }
                    key = key & 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000_u128 as i128 | next;
                }
            }
            txn.put(key.to_be_bytes(), event.fields.as_slice())
                .context("cannot write event")?;
            match txn.commit() {
                Ok(_) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store event");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Updates an old key-value pair to a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the database, the old key does
    /// not exist, or the database operation fails.
    pub fn update(&self, old: (&[u8], &[u8]), new: (&[u8], &[u8])) -> Result<()> {
        loop {
            let txn = self.inner.transaction();
            if let Some(old_value) = txn
                .get_for_update(old.0, super::EXCLUSIVE)
                .context("cannot read old entry")?
            {
                if old.1 != old_value.as_slice() {
                    bail!("old value mismatch");
                }
            } else {
                bail!("no such entry");
            };

            txn.put(new.0, new.1).context("failed to write new entry")?;
            if old.0 != new.0 {
                txn.delete(old.0).context("failed to delete old entry")?;
            }

            match txn.commit() {
                Ok(_) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventIterator<'i> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
}

impl<'i> Iterator for EventIterator<'i> {
    type Item = Result<(i128, Event), InvalidEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let (k, v) = self.inner.next().transpose().ok().flatten()?;

        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Some(Err(InvalidEvent::Key(k)));
        };
        let key = i128::from_be_bytes(key);
        let time = Utc.timestamp_nanos((key >> 64).try_into().expect("valid i64"));
        let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            return Some(Err(InvalidEvent::Key(k)));
        };
        match kind {
            EventKind::DnsCovertChannel => {
                let Ok(fields) = bincode::deserialize::<DnsEventFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::DnsCovertChannel(DnsCovertChannel::new(time, fields)),
                )))
            }
            EventKind::HttpThreat => {
                let Ok(fields) = bincode::deserialize::<HttpThreatFields>(v.as_ref()) else {
                        return Some(Err(InvalidEvent::Value(v)))
                    };
                Some(Ok((
                    key,
                    Event::HttpThreat(HttpThreat::new(fields.time, fields)),
                )))
            }
            EventKind::RdpBruteForce => {
                let Ok(fields) = bincode::deserialize::<RdpBruteForceFields>(v.as_ref()) else {
                        return Some(Err(InvalidEvent::Value(v)))
                    };
                Some(Ok((
                    key,
                    Event::RdpBruteForce(RdpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::RepeatedHttpSessions => {
                let Ok(fields) =
                    bincode::deserialize::<RepeatedHttpSessionsFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::RepeatedHttpSessions(RepeatedHttpSessions::new(time, &fields)),
                )))
            }
            EventKind::TorConnection => {
                let Ok(fields) = bincode::deserialize::<TorConnectionFields>(v.as_ref()) else {
                        return Some(Err(InvalidEvent::Value(v)));
                    };
                Some(Ok((
                    key,
                    Event::TorConnection(TorConnection::new(time, &fields)),
                )))
            }
            EventKind::DomainGenerationAlgorithm => {
                let Ok(fields) =
                    bincode::deserialize::<DgaFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, fields)),
                )))
            }
            EventKind::FtpBruteForce => {
                let Ok(fields) =
                    bincode::deserialize::<FtpBruteForceFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpBruteForce(FtpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::FtpPlainText => {
                let Ok(fields) =
                    bincode::deserialize::<FtpPlainTextFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpPlainText(FtpPlainText::new(time, fields)),
                )))
            }
            EventKind::PortScan => {
                let Ok(fields) =
                    bincode::deserialize::<PortScanFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::PortScan(PortScan::new(time, &fields)))))
            }
            EventKind::MultiHostPortScan => {
                let Ok(fields) =
                    bincode::deserialize::<MultiHostPortScanFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::MultiHostPortScan(MultiHostPortScan::new(time, &fields)),
                )))
            }
            EventKind::NonBrowser => {
                let Ok(fields) =
                    bincode::deserialize::<NonBrowserFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::NonBrowser(NonBrowser::new(time, &fields)))))
            }
            EventKind::LdapBruteForce => {
                let Ok(fields) =
                    bincode::deserialize::<LdapBruteForceFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapBruteForce(LdapBruteForce::new(time, &fields)),
                )))
            }
            EventKind::LdapPlainText => {
                let Ok(fields) =
                    bincode::deserialize::<LdapPlainTextFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapPlainText(LdapPlainText::new(time, fields)),
                )))
            }
            EventKind::ExternalDDos => {
                let Ok(fields) =
                    bincode::deserialize::<ExternalDDosFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::ExternalDDos(ExternalDDos::new(time, &fields)),
                )))
            }
            EventKind::Log => None,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum InvalidEvent {
    Key(Box<[u8]>),
    Value(Box<[u8]>),
}

#[derive(Deserialize, Serialize)]
pub struct Filter {
    pub name: String,
    pub directions: Option<Vec<FlowKind>>,
    pub keywords: Option<Vec<String>>,
    pub network_tags: Option<Vec<String>>,
    pub customers: Option<Vec<String>>,
    pub endpoints: Option<Vec<FilterEndpoint>>,
    pub sensors: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
    pub devices: Option<Vec<String>>,
    pub host_names: Option<Vec<String>>,
    pub user_ids: Option<Vec<String>>,
    pub user_names: Option<Vec<String>>,
    pub user_departments: Option<Vec<String>>,
    pub countries: Option<Vec<String>>,
    pub categories: Option<Vec<u8>>,
    pub levels: Option<Vec<u8>>,
    pub kinds: Option<Vec<String>>,
    pub learning_methods: Option<Vec<LearningMethod>>,
    pub confidence: Option<f32>,
}

pub type Id = u32;

#[derive(Clone, Deserialize, Serialize)]
pub struct FilterEndpoint {
    pub direction: Option<TrafficDirection>,
    pub predefined: Option<Id>,
    pub custom: Option<HostNetworkGroup>,
}

/// Traffic flow direction.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

pub struct Network {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub networks: HostNetworkGroup,
    pub customer_ids: Vec<u32>,
    pub tag_ids: Vec<u32>,
    pub creation_time: DateTime<Utc>,
}

impl Network {
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.networks.contains(addr)
    }

    #[must_use]
    pub fn has_tag(&self, tag_id: u32) -> bool {
        self.tag_ids.contains(&tag_id)
    }
}

impl FromKeyValue for Network {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        let mut entry = NetworkEntry::from_key_value(key, value)?;
        let id = u32::from_be_bytes(
            entry.key[entry.key.len() - size_of::<Id>()..]
                .try_into()
                .expect("should have four bytes"),
        );
        entry.key.truncate(entry.key.len() - size_of::<Id>());
        Ok(Self {
            id,
            name: String::from_utf8(entry.key).context("invalid key in database")?,
            description: entry.value.description,
            networks: entry.value.networks,
            customer_ids: entry.value.customer_ids,
            tag_ids: entry.value.tag_ids,
            creation_time: entry.value.creation_time,
        })
    }
}

pub struct NetworkEntry {
    pub key: Vec<u8>,
    pub value: NetworkEntryValue,
}

impl NetworkEntry {
    pub fn delete_customer(&mut self, customer_id: u32) -> bool {
        let prev_len = self.value.customer_ids.len();
        self.value.customer_ids.retain(|&id| id != customer_id);
        prev_len != self.value.customer_ids.len()
    }
}

impl FromKeyValue for NetworkEntry {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(Self {
            key: key.to_vec(),
            value: bincode::DefaultOptions::new()
                .deserialize(value)
                .context("failed to deserialize")?,
        })
    }
}

impl Indexable for NetworkEntry {
    fn key(&self) -> &[u8] {
        &self.key[..self.key.len() - size_of::<Id>()]
    }

    fn indexed_key(&self) -> &[u8] {
        &self.key
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(&self.value)
            .expect("serializable")
    }

    fn set_index(&mut self, index: Id) {
        let offset = self.key.len() - size_of::<Id>();
        self.key[offset..].copy_from_slice(&index.to_be_bytes());
    }
}

#[derive(Deserialize, Serialize)]
pub struct NetworkEntryValue {
    pub description: String,
    pub networks: HostNetworkGroup,
    pub customer_ids: Vec<u32>,
    pub tag_ids: Vec<u32>,
    pub creation_time: DateTime<Utc>,
}

/// Possible network types of `CustomerNetwork`.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum NetworkType {
    Intranet,
    Extranet,
    Gateway,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrafficDirection {
    From,
    To,
}

fn common_count_ip_address(
    counter: &mut HashMap<IpAddr, usize>,
    src_addr: IpAddr,
    dst_addr: IpAddr,
) {
    let entry = counter.entry(src_addr).or_insert(0);
    *entry += 1;
    let entry = counter.entry(dst_addr).or_insert(0);
    *entry += 1;
}

fn common_count_country(
    locator: &Option<Arc<Mutex<ip2location::DB>>>,
    counter: &mut HashMap<String, usize>,
    src_addr: IpAddr,
    dst_addr: IpAddr,
) {
    let src_country = locator.as_ref().map_or_else(
        || "ZZ".to_string(),
        |mutex| {
            if let Ok(mut locator) = mutex.lock() {
                find_ip_country(&mut locator, src_addr)
            } else {
                "ZZ".to_string()
            }
        },
    );
    let dst_country = locator.as_ref().map_or_else(
        || "ZZ".to_string(),
        |mutex| {
            if let Ok(mut locator) = mutex.lock() {
                find_ip_country(&mut locator, dst_addr)
            } else {
                "ZZ".to_string()
            }
        },
    );

    if src_country != dst_country {
        let entry = counter.entry(src_country).or_insert(0);
        *entry += 1;
    }
    let entry = counter.entry(dst_country).or_insert(0);
    *entry += 1;
}

pub fn find_ip_country(locator: &mut ip2location::DB, addr: IpAddr) -> String {
    locator
        .ip_lookup(addr)
        .map(|r| get_record_country_short_name(&r))
        .ok()
        .flatten()
        .unwrap_or_else(|| "XX".to_string())
}

fn eq_ip_country(
    locator: &mut MutexGuard<ip2location::DB>,
    addr: IpAddr,
    country: [u8; 2],
) -> bool {
    locator
        .ip_lookup(addr)
        .ok()
        .and_then(|r| get_record_country_short_name(&r))
        .map_or(false, |c| c.as_bytes() == country)
}

fn get_record_country_short_name(record: &ip2location::Record) -> Option<String> {
    use ip2location::Record;
    match record {
        Record::ProxyDb(r) => r.country.as_ref().map(|c| c.short_name.clone()),
        Record::LocationDb(r) => r.country.as_ref().map(|c| c.short_name.clone()),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        event::DgaFields, event::DnsEventFields, DomainGenerationAlgorithm, EventKind,
        EventMessage, Store,
    };
    use bincode::Options;
    use chrono::{TimeZone, Utc};
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    fn example_message() -> EventMessage {
        let codec = bincode::DefaultOptions::new();
        let fields = DnsEventFields {
            source: "collector1".to_string(),
            session_end_time: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 53,
            proto: 17,
            query: "foo.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
            confidence: 0.8,
        };
        EventMessage {
            time: Utc::now(),
            kind: EventKind::DnsCovertChannel,
            fields: codec.serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn event_db_put() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        assert!(db.iter_forward().next().is_none());

        let msg = example_message();
        db.put(&msg).unwrap();
        let mut iter = db.iter_forward();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());

        db.put(&msg).unwrap();
        let mut iter = db.iter_forward();
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[tokio::test]
    async fn event_display_for_syslog() {
        let fields = DgaFields {
            source: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            duration: Utc::now().timestamp_nanos(),
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
            confidence: 0.8,
        };
        let msg = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::DomainGenerationAlgorithm,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let syslog_message = format!("{msg}");
        assert_eq!(syslog_message, "1970-01-01T00:01:01+00:00,DomainGenerationAlgorithm,127.0.0.1,10000,127.0.0.2,80,6,DGA,3,GET,example.com,/uri/path,-,200,browser".to_string());

        let dga = DomainGenerationAlgorithm::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            fields,
        );
        let dga_display = format!("{dga}");
        assert!(dga_display.ends_with(
            ",127.0.0.1,10000,127.0.0.2,80,6,DGA,GET,example.com,/uri/path,-,200,browser"
        ));
    }

    #[tokio::test]
    async fn event_db_backup() {
        use rocksdb::backup::{BackupEngine, BackupEngineOptions, RestoreOptions};
        use tokio::sync::RwLock;

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path()).unwrap(),
        ));
        {
            let store = store.read().await;
            let db = store.events();
            assert!(db.iter_forward().next().is_none());

            let msg = example_message();

            db.put(&msg).unwrap();
            {
                let mut iter = db.iter_forward();
                assert!(iter.next().is_some());
                assert!(iter.next().is_none());
            }
        }
        // backing up
        {
            let mut store = store.write().await;
            let res = store.backup(true, 1);
            assert!(res.is_ok());
        }

        // more operations
        {
            let store = store.read().await;
            let db = store.events();
            let msg = example_message();
            db.put(&msg).unwrap();
            {
                let mut iter = db.iter_forward();
                assert!(iter.next().is_some());
                assert!(iter.next().is_some());
                assert!(iter.next().is_none());
            }
        }
        // restoring the backup
        drop(store);

        let mut backup = BackupEngine::open(
            &BackupEngineOptions::new(backup_dir.path().join("states.db")).unwrap(),
            &rocksdb::Env::new().unwrap(),
        )
        .unwrap();
        assert!(backup
            .restore_from_backup(
                db_dir.path().join("states.db"),
                db_dir.path().join("states.db"),
                &RestoreOptions::default(),
                1,
            )
            .is_ok());

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path()).unwrap(),
        ));
        {
            let store = store.read().await;
            let db = store.events();
            let mut iter = db.iter_forward();
            assert!(iter.next().is_some());
            assert!(iter.next().is_none());
        }
        let info = backup.get_backup_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].backup_id, 1);
    }
}
