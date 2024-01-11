#![allow(clippy::too_many_lines)]
mod common;
mod conn;
mod dcerpc;
mod dns;
mod ftp;
mod http;
mod kerberos;
mod ldap;
mod log;
mod mqtt;
mod network;
mod nfs;
mod ntlm;
mod rdp;
mod smb;
mod smtp;
mod ssh;
mod sysmon;
mod tls;
mod tor;

use self::{common::Match, http::RepeatedHttpSessionsFields};
pub use self::{
    common::TriageScore,
    conn::{
        BlockListConn, BlockListConnFields, ExternalDdos, ExternalDdosFields, MultiHostPortScan,
        MultiHostPortScanFields, PortScan, PortScanFields,
    },
    dcerpc::{BlockListDceRpc, BlockListDceRpcFields},
    dns::{
        BlockListDns, BlockListDnsFields, CryptocurrencyMiningPool, CryptocurrencyMiningPoolFields,
        DnsCovertChannel, DnsEventFields,
    },
    ftp::{
        BlockListFtp, BlockListFtpFields, FtpBruteForce, FtpBruteForceFields, FtpPlainText,
        FtpPlainTextFields,
    },
    http::{
        BlockListHttp, BlockListHttpFields, DgaFields, DomainGenerationAlgorithm, HttpThreat,
        HttpThreatFields, NonBrowser, NonBrowserFields, RepeatedHttpSessions,
    },
    kerberos::{BlockListKerberos, BlockListKerberosFields},
    ldap::{
        BlockListLdap, BlockListLdapFields, LdapBruteForce, LdapBruteForceFields, LdapPlainText,
        LdapPlainTextFields,
    },
    log::ExtraThreat,
    mqtt::{BlockListMqtt, BlockListMqttFields},
    network::NetworkThreat,
    nfs::{BlockListNfs, BlockListNfsFields},
    ntlm::{BlockListNtlm, BlockListNtlmFields},
    rdp::{BlockListRdp, BlockListRdpFields, RdpBruteForce, RdpBruteForceFields},
    smb::{BlockListSmb, BlockListSmbFields},
    smtp::{BlockListSmtp, BlockListSmtpFields},
    ssh::{BlockListSsh, BlockListSshFields},
    sysmon::WindowsThreat,
    tls::{BlockListTls, BlockListTlsFields},
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
use rocksdb::IteratorMode;
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
const DOMAIN_GENERATION_ALGORITHM: &str = "Domain Generation Algorithm";
const FTP_BRUTE_FORCE: &str = "FTP Brute Force";
const FTP_PLAIN_TEXT: &str = "FTP Plain text";
const PORT_SCAN: &str = "Port Scan";
const MULTI_HOST_PORT_SCAN: &str = "Multi Host Port Scan";
const EXTERNAL_DDOS: &str = "External Ddos";
const NON_BROWSER: &str = "Non Browser";
const LDAP_BRUTE_FORCE: &str = "LDAP Brute Force";
const LDAP_PLAIN_TEXT: &str = "LDAP Plain Text";
const CRYPTOCURRENCY_MINING_POOL: &str = "Cryptocurrency Mining Pool";
const BLOCK_LIST: &str = "Block List";
const WINDOWS_THREAT_EVENT: &str = "Windows Threat Events";
const NETWORK_THREAT_EVENT: &str = "Network Threat Events";
const MISC_LOG_THREAT: &str = "Log Threat";

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
    ExternalDdos(ExternalDdos),

    /// Non-browser user agent detected in HTTP request message.
    NonBrowser(NonBrowser),

    /// Brute force attacks against LDAP.
    LdapBruteForce(LdapBruteForce),

    /// Plain text password is used for the LDAP connection.
    LdapPlainText(LdapPlainText),

    /// An event that occurs when it is determined that there is a connection to a cryptocurrency mining network
    CryptocurrencyMiningPool(CryptocurrencyMiningPool),

    BlockList(RecordType),

    WindowsThreat(WindowsThreat),

    NetworkThreat(NetworkThreat),

    ExtraThreat(ExtraThreat),
}

pub enum RecordType {
    Conn(BlockListConn),
    Dns(BlockListDns),
    DceRpc(BlockListDceRpc),
    Ftp(BlockListFtp),
    Http(BlockListHttp),
    Kerberos(BlockListKerberos),
    Ldap(BlockListLdap),
    Mqtt(BlockListMqtt),
    Nfs(BlockListNfs),
    Ntlm(BlockListNtlm),
    Rdp(BlockListRdp),
    Smb(BlockListSmb),
    Smtp(BlockListSmtp),
    Ssh(BlockListSsh),
    Tls(BlockListTls),
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
            Event::ExternalDdos(event) => event.matches(locator, filter),
            Event::NonBrowser(event) => event.matches(locator, filter),
            Event::LdapBruteForce(event) => event.matches(locator, filter),
            Event::LdapPlainText(event) => event.matches(locator, filter),
            Event::CryptocurrencyMiningPool(event) => event.matches(locator, filter),
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => conn_event.matches(locator, filter),
                RecordType::Dns(dns_event) => dns_event.matches(locator, filter),
                RecordType::DceRpc(dcerpc_event) => dcerpc_event.matches(locator, filter),
                RecordType::Ftp(ftp_event) => ftp_event.matches(locator, filter),
                RecordType::Http(http_event) => http_event.matches(locator, filter),
                RecordType::Kerberos(kerberos_event) => kerberos_event.matches(locator, filter),
                RecordType::Ldap(ldap_event) => ldap_event.matches(locator, filter),
                RecordType::Mqtt(mqtt_event) => mqtt_event.matches(locator, filter),
                RecordType::Nfs(nfs_event) => nfs_event.matches(locator, filter),
                RecordType::Ntlm(ntlm_event) => ntlm_event.matches(locator, filter),
                RecordType::Rdp(rdp_event) => rdp_event.matches(locator, filter),
                RecordType::Smb(smb_event) => smb_event.matches(locator, filter),
                RecordType::Smtp(smtp_event) => smtp_event.matches(locator, filter),
                RecordType::Ssh(ssh_event) => ssh_event.matches(locator, filter),
                RecordType::Tls(tls_event) => tls_event.matches(locator, filter),
            },
            Event::WindowsThreat(event) => event.matches(locator, filter),
            Event::NetworkThreat(event) => event.matches(locator, filter),
            Event::ExtraThreat(event) => event.matches(locator, filter),
        }
    }

    fn address_pair(
        &self,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<(Option<IpAddr>, Option<IpAddr>)> {
        let mut addr_pair = (None, None);
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), None);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), None);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (None, Some(event.dst_addr));
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(conn_event.src_addr), Some(conn_event.dst_addr));
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(dns_event.src_addr), Some(dns_event.dst_addr));
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(dcerpc_event.src_addr), Some(dcerpc_event.dst_addr));
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(ftp_event.src_addr), Some(ftp_event.dst_addr));
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(http_event.src_addr), Some(http_event.dst_addr));
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(kerberos_event.src_addr), Some(kerberos_event.dst_addr));
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(ldap_event.src_addr), Some(ldap_event.dst_addr));
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(mqtt_event.src_addr), Some(mqtt_event.dst_addr));
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(nfs_event.src_addr), Some(nfs_event.dst_addr));
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(ntlm_event.src_addr), Some(ntlm_event.dst_addr));
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(rdp_event.src_addr), Some(rdp_event.dst_addr));
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(smb_event.src_addr), Some(smb_event.dst_addr));
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(smtp_event.src_addr), Some(smtp_event.dst_addr));
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(ssh_event.src_addr), Some(ssh_event.dst_addr));
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(tls_event.src_addr), Some(tls_event.dst_addr));
                    }
                }
            },
            Event::WindowsThreat(_event) => {}
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::ExtraThreat(_event) => {}
        }
        Ok(addr_pair)
    }

    fn kind(
        &self,
        locator: Option<Arc<Mutex<ip2location::DB>>>,
        filter: &EventFilter,
    ) -> Result<Option<&'static str>> {
        let mut kind = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(DNS_COVERT_CHANNEL);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(HTTP_THREAT);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(RDP_BRUTE_FORCE);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(REPEATED_HTTP_SESSIONS);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(TOR_CONNECTION);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(DOMAIN_GENERATION_ALGORITHM);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(FTP_BRUTE_FORCE);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(FTP_PLAIN_TEXT);
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(PORT_SCAN);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(MULTI_HOST_PORT_SCAN);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(EXTERNAL_DDOS);
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(NON_BROWSER);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(LDAP_BRUTE_FORCE);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(LDAP_PLAIN_TEXT);
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(CRYPTOCURRENCY_MINING_POOL);
                }
            }
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(WINDOWS_THREAT_EVENT);
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(NETWORK_THREAT_EVENT);
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(MISC_LOG_THREAT);
                }
            }
        }
        Ok(kind)
    }

    // TODO: Need to implement country counting for `WindowsThreat`.
    // 1. for Network Connection: count country via ip
    // 2. for other Sysmon events: count the country by KR.
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
        let addr_pair = self.address_pair(locator.clone(), filter)?;

        let mut src_country = "ZZ".to_string();
        let mut dst_country = "ZZ".to_string();
        if let Some(mutex) = &locator {
            if let Ok(mut guarded_locator) = mutex.lock() {
                if let Some(src_addr) = addr_pair.0 {
                    src_country = find_ip_country(&mut guarded_locator, src_addr);
                }
                if let Some(dst_addr) = addr_pair.1 {
                    dst_country = find_ip_country(&mut guarded_locator, dst_addr);
                }
            }
        }
        if src_country != dst_country && addr_pair.0.is_some() && addr_pair.1.is_some() {
            counter
                .entry(src_country)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }
        if addr_pair.1.is_some() {
            counter
                .entry(dst_country)
                .and_modify(|e| *e += 1)
                .or_insert(1);
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
        let mut category = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CommandAndControl);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Reconnaissance);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Discovery);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Exfiltration);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CommandAndControl);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CommandAndControl);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CredentialAccess);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::LateralMovement);
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Reconnaissance);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Reconnaissance);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Impact);
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CommandAndControl);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CredentialAccess);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::LateralMovement);
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::CommandAndControl);
                }
            }
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        category = Some(EventCategory::InitialAccess);
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Impact);
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Reconnaissance);
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(EventCategory::Reconnaissance);
                }
            }
        };

        if let Some(category) = category {
            counter.entry(category).and_modify(|e| *e += 1).or_insert(1);
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
        let addr_pair = self.address_pair(locator, filter)?;

        if let Some(src_addr) = addr_pair.0 {
            counter.entry(src_addr).and_modify(|e| *e += 1).or_insert(1);
        }
        if let Some(dst_addr) = addr_pair.1 {
            counter.entry(dst_addr).and_modify(|e| *e += 1).or_insert(1);
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
        let addr_pair = self.address_pair(locator, filter)?;

        if let Some(src_addr) = addr_pair.0 {
            if let Some(dst_addr) = addr_pair.1 {
                counter
                    .entry((src_addr, dst_addr))
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
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
        let addr_pair = self.address_pair(locator.clone(), filter)?;
        let kind = self.kind(locator, filter)?;

        if let Some(src_addr) = addr_pair.0 {
            if let Some(dst_addr) = addr_pair.1 {
                if let Some(kind) = kind {
                    counter
                        .entry((src_addr, dst_addr, kind))
                        .and_modify(|e| *e += 1)
                        .or_insert(1);
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
        let addr_pair = self.address_pair(locator, filter)?;

        if let Some(src_addr) = addr_pair.0 {
            counter.entry(src_addr).and_modify(|e| *e += 1).or_insert(1);
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
        let addr_pair = self.address_pair(locator, filter)?;

        if let Some(dst_addr) = addr_pair.1 {
            counter.entry(dst_addr).and_modify(|e| *e += 1).or_insert(1);
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
        let kind = if let Event::HttpThreat(event) = self {
            if event.matches(locator, filter)?.0 {
                Some(event.attack_kind.to_string())
            } else {
                None
            }
        } else {
            self.kind(locator, filter)?.map(ToString::to_string)
        };

        if let Some(kind) = kind {
            counter.entry(kind).and_modify(|e| *e += 1).or_insert(1);
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
        let mut level = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(LOW);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        level = Some(MEDIUM);
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(MEDIUM);
                }
            }
        }

        if let Some(level) = level {
            counter.entry(level).and_modify(|e| *e += 1).or_insert(1);
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
        let addr_pair = self.address_pair(locator, filter)?;

        if let Some(src_addr) = addr_pair.0 {
            if let Some(id) = find_network(src_addr, networks) {
                counter.entry(id).and_modify(|e| *e += 1).or_insert(1);
            }
        }
        if let Some(dst_addr) = addr_pair.1 {
            if let Some(id) = find_network(dst_addr, networks) {
                counter.entry(id).and_modify(|e| *e += 1).or_insert(1);
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
            Event::ExternalDdos(event) => {
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
            Event::CryptocurrencyMiningPool(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::BlockList(record_type) => match record_type {
                RecordType::Conn(conn_event) => {
                    conn_event.triage_scores = Some(triage_scores);
                }
                RecordType::Dns(dns_event) => {
                    dns_event.triage_scores = Some(triage_scores);
                }
                RecordType::DceRpc(dcerpc_event) => {
                    dcerpc_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ftp(ftp_event) => {
                    ftp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Http(http_event) => {
                    http_event.triage_scores = Some(triage_scores);
                }
                RecordType::Kerberos(kerberos_event) => {
                    kerberos_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ldap(ldap_event) => {
                    ldap_event.triage_scores = Some(triage_scores);
                }
                RecordType::Mqtt(mqtt_event) => {
                    mqtt_event.triage_scores = Some(triage_scores);
                }
                RecordType::Nfs(nfs_event) => {
                    nfs_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ntlm(ntlm_event) => {
                    ntlm_event.triage_scores = Some(triage_scores);
                }
                RecordType::Rdp(rdp_event) => {
                    rdp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Smb(smb_event) => {
                    smb_event.triage_scores = Some(triage_scores);
                }
                RecordType::Smtp(smtp_event) => {
                    smtp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ssh(ssh_event) => {
                    ssh_event.triage_scores = Some(triage_scores);
                }
                RecordType::Tls(tls_event) => {
                    tls_event.triage_scores = Some(triage_scores);
                }
            },
            Event::WindowsThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::NetworkThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::ExtraThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
        }
    }
}

fn find_network(ip: IpAddr, networks: &[Network]) -> Option<u32> {
    for net in networks {
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
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlockListConn,
    BlockListDns,
    BlockListDceRpc,
    BlockListFtp,
    BlockListHttp,
    BlockListKerberos,
    BlockListLdap,
    BlockListMqtt,
    BlockListNfs,
    BlockListNtlm,
    BlockListRdp,
    BlockListSmb,
    BlockListSmtp,
    BlockListSsh,
    BlockListTls,
    WindowsThreat,
    NetworkThreat,
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
            moderate_kinds_by(kinds, &["crypto", "currency"], "crypto currency");
            moderate_kinds_by(kinds, &["block", "list", "conn"], "block list conn");
            moderate_kinds_by(kinds, &["block", "list", "dns"], "block list dns");
            moderate_kinds_by(kinds, &["block", "list", "dcerpc"], "block list dcerpc");
            moderate_kinds_by(kinds, &["block", "list", "ftp"], "block list ftp");
            moderate_kinds_by(kinds, &["block", "list", "http"], "block list http");
            moderate_kinds_by(kinds, &["block", "list", "kerberos"], "block list kerberos");
            moderate_kinds_by(kinds, &["block", "list", "ldap"], "block list ldap");
            moderate_kinds_by(kinds, &["block", "list", "mqtt"], "block list mqtt");
            moderate_kinds_by(kinds, &["block", "list", "nfs"], "block list nfs");
            moderate_kinds_by(kinds, &["block", "list", "ntlm"], "block list ntlm");
            moderate_kinds_by(kinds, &["block", "list", "rdp"], "block list rdp");
            moderate_kinds_by(kinds, &["block", "list", "smb"], "block list smb");
            moderate_kinds_by(kinds, &["block", "list", "smtp"], "block list stmp");
            moderate_kinds_by(kinds, &["block", "list", "ssh"], "block list ssh");
            moderate_kinds_by(kinds, &["block", "list", "tls"], "block list tls");
            moderate_kinds_by(kinds, &["windows", "threat"], "windows threat");
            moderate_kinds_by(kinds, &["network", "threat"], "network threat");
            moderate_kinds_by(kinds, &["extra", "threat"], "extra threat");
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
            EventKind::ExternalDdos => {
                if let Ok(fields) = bincode::deserialize::<ExternalDdosFields>(&self.fields) {
                    write!(f, "ExternalDdos,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::CryptocurrencyMiningPool => {
                if let Ok(fields) =
                    bincode::deserialize::<CryptocurrencyMiningPoolFields>(&self.fields)
                {
                    write!(f, "CryptocurrencyMiningPool,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListConn => {
                if let Ok(fields) = bincode::deserialize::<BlockListConnFields>(&self.fields) {
                    write!(f, "BlockListConn,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListDns => {
                if let Ok(fields) = bincode::deserialize::<BlockListDnsFields>(&self.fields) {
                    write!(f, "BlockListDns,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListDceRpc => {
                if let Ok(fields) = bincode::deserialize::<BlockListDceRpcFields>(&self.fields) {
                    write!(f, "BlockListDceRpc,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListFtp => {
                if let Ok(fields) = bincode::deserialize::<BlockListFtpFields>(&self.fields) {
                    write!(f, "BlockListFtp,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListHttp => {
                if let Ok(fields) = bincode::deserialize::<BlockListHttpFields>(&self.fields) {
                    write!(f, "BlockListHttp,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListKerberos => {
                if let Ok(fields) = bincode::deserialize::<BlockListKerberosFields>(&self.fields) {
                    write!(f, "BlockListKerberos,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListLdap => {
                if let Ok(fields) = bincode::deserialize::<BlockListLdapFields>(&self.fields) {
                    write!(f, "BlockListLdap,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListMqtt => {
                if let Ok(fields) = bincode::deserialize::<BlockListMqttFields>(&self.fields) {
                    write!(f, "BlcokListMqtt,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListNfs => {
                if let Ok(fields) = bincode::deserialize::<BlockListNfsFields>(&self.fields) {
                    write!(f, "BlockListNfs,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListNtlm => {
                if let Ok(fields) = bincode::deserialize::<BlockListNtlmFields>(&self.fields) {
                    write!(f, "BlockListNtlm,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListRdp => {
                if let Ok(fields) = bincode::deserialize::<BlockListRdpFields>(&self.fields) {
                    write!(f, "BlockListRdp,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListSmb => {
                if let Ok(fields) = bincode::deserialize::<BlockListSmbFields>(&self.fields) {
                    write!(f, "BlockListSmb,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListSmtp => {
                if let Ok(fields) = bincode::deserialize::<BlockListSmtpFields>(&self.fields) {
                    write!(f, "BlockListSmtp,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListSsh => {
                if let Ok(fields) = bincode::deserialize::<BlockListSshFields>(&self.fields) {
                    write!(f, "BlockListSsh,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::BlockListTls => {
                if let Ok(fields) = bincode::deserialize::<BlockListTlsFields>(&self.fields) {
                    write!(f, "BlockListTls,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::WindowsThreat => {
                if let Ok(fields) = bincode::deserialize::<WindowsThreat>(&self.fields) {
                    write!(f, "WindowsThreat,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::NetworkThreat => {
                if let Ok(fields) = bincode::deserialize::<NetworkThreat>(&self.fields) {
                    write!(f, "NetworkThreat,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
            EventKind::ExtraThreat => {
                if let Ok(fields) = bincode::deserialize::<ExtraThreat>(&self.fields) {
                    write!(f, "ExtraThreat,{fields}")
                } else {
                    write!(f, "invalid event")
                }
            }
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

    /// Stores a new event into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn put(&self, event: &EventMessage) -> Result<i128> {
        use anyhow::anyhow;
        let mut key = i128::from(event.time.timestamp_nanos_opt().unwrap_or(i64::MAX)) << 64
            | event
                .kind
                .to_i128()
                .ok_or(anyhow!("`EventKind` exceeds i128::MAX"))?
                << 32;
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
                Ok(()) => break,
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
                Ok(()) => break,
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
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::HttpThreat(HttpThreat::new(fields.time, fields)),
                )))
            }
            EventKind::RdpBruteForce => {
                let Ok(fields) = bincode::deserialize::<RdpBruteForceFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::RdpBruteForce(RdpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::RepeatedHttpSessions => {
                let Ok(fields) = bincode::deserialize::<RepeatedHttpSessionsFields>(v.as_ref())
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
                let Ok(fields) = bincode::deserialize::<DgaFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, fields)),
                )))
            }
            EventKind::FtpBruteForce => {
                let Ok(fields) = bincode::deserialize::<FtpBruteForceFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpBruteForce(FtpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::FtpPlainText => {
                let Ok(fields) = bincode::deserialize::<FtpPlainTextFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpPlainText(FtpPlainText::new(time, fields)),
                )))
            }
            EventKind::PortScan => {
                let Ok(fields) = bincode::deserialize::<PortScanFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::PortScan(PortScan::new(time, &fields)))))
            }
            EventKind::MultiHostPortScan => {
                let Ok(fields) = bincode::deserialize::<MultiHostPortScanFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::MultiHostPortScan(MultiHostPortScan::new(time, &fields)),
                )))
            }
            EventKind::NonBrowser => {
                let Ok(fields) = bincode::deserialize::<NonBrowserFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::NonBrowser(NonBrowser::new(time, &fields)))))
            }
            EventKind::LdapBruteForce => {
                let Ok(fields) = bincode::deserialize::<LdapBruteForceFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapBruteForce(LdapBruteForce::new(time, &fields)),
                )))
            }
            EventKind::LdapPlainText => {
                let Ok(fields) = bincode::deserialize::<LdapPlainTextFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapPlainText(LdapPlainText::new(time, fields)),
                )))
            }
            EventKind::ExternalDdos => {
                let Ok(fields) = bincode::deserialize::<ExternalDdosFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::ExternalDdos(ExternalDdos::new(time, &fields)),
                )))
            }
            EventKind::CryptocurrencyMiningPool => {
                let Ok(fields) = bincode::deserialize::<CryptocurrencyMiningPoolFields>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::CryptocurrencyMiningPool(CryptocurrencyMiningPool::new(time, fields)),
                )))
            }
            EventKind::BlockListConn => {
                let Ok(fields) = bincode::deserialize::<BlockListConnFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Conn(BlockListConn::new(time, fields))),
                )))
            }
            EventKind::BlockListDns => {
                let Ok(fields) = bincode::deserialize::<BlockListDnsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Dns(BlockListDns::new(time, fields))),
                )))
            }
            EventKind::BlockListDceRpc => {
                let Ok(fields) = bincode::deserialize::<BlockListDceRpcFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::DceRpc(BlockListDceRpc::new(time, fields))),
                )))
            }
            EventKind::BlockListFtp => {
                let Ok(fields) = bincode::deserialize::<BlockListFtpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Ftp(BlockListFtp::new(time, fields))),
                )))
            }
            EventKind::BlockListHttp => {
                let Ok(fields) = bincode::deserialize::<BlockListHttpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Http(BlockListHttp::new(time, fields))),
                )))
            }
            EventKind::BlockListKerberos => {
                let Ok(fields) = bincode::deserialize::<BlockListKerberosFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Kerberos(BlockListKerberos::new(time, fields))),
                )))
            }
            EventKind::BlockListLdap => {
                let Ok(fields) = bincode::deserialize::<BlockListLdapFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Ldap(BlockListLdap::new(time, fields))),
                )))
            }
            EventKind::BlockListMqtt => {
                let Ok(fields) = bincode::deserialize::<BlockListMqttFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Mqtt(BlockListMqtt::new(time, fields))),
                )))
            }
            EventKind::BlockListNfs => {
                let Ok(fields) = bincode::deserialize::<BlockListNfsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Nfs(BlockListNfs::new(time, fields))),
                )))
            }
            EventKind::BlockListNtlm => {
                let Ok(fields) = bincode::deserialize::<BlockListNtlmFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Ntlm(BlockListNtlm::new(time, fields))),
                )))
            }
            EventKind::BlockListRdp => {
                let Ok(fields) = bincode::deserialize::<BlockListRdpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Rdp(BlockListRdp::new(time, fields))),
                )))
            }
            EventKind::BlockListSmb => {
                let Ok(fields) = bincode::deserialize::<BlockListSmbFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Smb(BlockListSmb::new(time, fields))),
                )))
            }
            EventKind::BlockListSmtp => {
                let Ok(fields) = bincode::deserialize::<BlockListSmtpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Smtp(BlockListSmtp::new(time, fields))),
                )))
            }
            EventKind::BlockListSsh => {
                let Ok(fields) = bincode::deserialize::<BlockListSshFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Ssh(BlockListSsh::new(time, fields))),
                )))
            }
            EventKind::BlockListTls => {
                let Ok(fields) = bincode::deserialize::<BlockListTlsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::BlockList(RecordType::Tls(BlockListTls::new(time, fields))),
                )))
            }
            EventKind::WindowsThreat => {
                let Ok(fields) = bincode::deserialize::<WindowsThreat>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::WindowsThreat(fields))))
            }
            EventKind::NetworkThreat => {
                let Ok(fields) = bincode::deserialize::<NetworkThreat>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::NetworkThreat(fields))))
            }
            EventKind::ExtraThreat => {
                let Ok(fields) = bincode::deserialize::<ExtraThreat>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::ExtraThreat(fields))))
            }
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
        Record::ProxyDb(r) => r
            .country
            .as_ref()
            .map(|c| c.short_name.clone().into_owned()),
        Record::LocationDb(r) => r
            .country
            .as_ref()
            .map(|c| c.short_name.clone().into_owned()),
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
            duration: Utc::now().timestamp_nanos_opt().unwrap(),
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
