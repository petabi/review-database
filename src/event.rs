#![allow(clippy::too_many_lines)]
#![allow(clippy::useless_nonzero_new_unchecked)]
mod bootp;
mod common;
mod conn;
mod dcerpc;
mod dhcp;
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

use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::{self},
    net::IpAddr,
    num::NonZeroU8,
};

use aho_corasick::AhoCorasickBuilder;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeZone, Utc, serde::ts_nanoseconds};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{RngCore, rng};
pub use rocksdb::Direction;
use rocksdb::{DBIteratorWithThreadMode, IteratorMode};
use serde::{Deserialize, Serialize};

use self::common::Match;
pub use self::{
    bootp::{BlocklistBootp, BlocklistBootpFields},
    common::TriageScore,
    conn::{
        BlocklistConn, BlocklistConnFields, ExternalDdos, ExternalDdosFields, MultiHostPortScan,
        MultiHostPortScanFields, PortScan, PortScanFields,
    },
    dcerpc::{BlocklistDceRpc, BlocklistDceRpcFields},
    dhcp::{BlocklistDhcp, BlocklistDhcpFields},
    dns::{
        BlocklistDns, BlocklistDnsFields, CryptocurrencyMiningPool, CryptocurrencyMiningPoolFields,
        DnsCovertChannel, DnsEventFields, LockyRansomware,
    },
    ftp::{BlocklistFtp, FtpBruteForce, FtpBruteForceFields, FtpEventFields, FtpPlainText},
    http::{
        BlocklistHttp, BlocklistHttpFields, DgaFields, DomainGenerationAlgorithm, HttpThreat,
        HttpThreatFields, NonBrowser, RepeatedHttpSessions, RepeatedHttpSessionsFields,
    },
    kerberos::{BlocklistKerberos, BlocklistKerberosFields},
    ldap::{BlocklistLdap, LdapBruteForce, LdapBruteForceFields, LdapEventFields, LdapPlainText},
    log::ExtraThreat,
    mqtt::{BlocklistMqtt, BlocklistMqttFields},
    network::NetworkThreat,
    nfs::{BlocklistNfs, BlocklistNfsFields},
    ntlm::{BlocklistNtlm, BlocklistNtlmFields},
    rdp::{BlocklistRdp, BlocklistRdpFields, RdpBruteForce, RdpBruteForceFields},
    smb::{BlocklistSmb, BlocklistSmbFields},
    smtp::{BlocklistSmtp, BlocklistSmtpFields},
    ssh::{BlocklistSsh, BlocklistSshFields},
    sysmon::WindowsThreat,
    tls::{BlocklistTls, BlocklistTlsFields, SuspiciousTlsTraffic},
    tor::{HttpEventFields, TorConnection},
};
use super::{
    Customer, EventCategory, Network, TriagePolicy,
    types::{Endpoint, HostNetworkGroup},
};

// event levels (currently unused ones commented out)
// const VERY_LOW: NonZeroU8 =NonZeroU8::new(1).expect("eThe constant holds the nonzero value 1, which is always valid");
const LOW: NonZeroU8 =
    NonZeroU8::new(2).expect("The constant holds the nonzero value 2, which is always valid");
const MEDIUM: NonZeroU8 =
    NonZeroU8::new(3).expect("The constant holds the nonzero value 3, which is always valid");
const HIGH: NonZeroU8 =
    NonZeroU8::new(4).expect("The constant holds the nonzero value 4, which is always valid");
// const VERY_HIGH: NonZeroU8 =NonZeroU8::new(5).expect("The constant holds the nonzero value 5, which is always valid");

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
const LOCKY_RANSOMWARE: &str = "Locky Ransomware";
const SUSPICIOUS_TLS_TRAFFIC: &str = "Suspicious TLS Traffic";

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

    Blocklist(RecordType),

    WindowsThreat(WindowsThreat),

    NetworkThreat(NetworkThreat),

    ExtraThreat(ExtraThreat),

    LockyRansomware(LockyRansomware),

    SuspiciousTlsTraffic(SuspiciousTlsTraffic),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (event_kind, category) = self.kind_and_category();
        let event_kind = format!("{event_kind:?}");
        let category = format!("{category:?}");

        match self {
            Event::DnsCovertChannel(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::HttpThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::RdpBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::RepeatedHttpSessions(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::TorConnection(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::DomainGenerationAlgorithm(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::FtpBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::FtpPlainText(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::PortScan(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::MultiHostPortScan(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::ExternalDdos(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::NonBrowser(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::LdapBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::LdapPlainText(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::CryptocurrencyMiningPool(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Conn(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::DceRpc(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Dhcp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Dns(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Ftp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Http(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Kerberos(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Ldap(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Mqtt(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Nfs(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Ntlm(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Rdp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Smb(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Smtp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Ssh(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
                RecordType::Tls(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        event.time.to_rfc3339(),
                    )
                }
            },
            Event::WindowsThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::NetworkThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::ExtraThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::LockyRansomware(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
            Event::SuspiciousTlsTraffic(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    event.time.to_rfc3339(),
                )
            }
        }
    }
}

pub enum RecordType {
    Conn(BlocklistConn),
    Dns(BlocklistDns),
    DceRpc(BlocklistDceRpc),
    Ftp(BlocklistFtp),
    Http(BlocklistHttp),
    Kerberos(BlocklistKerberos),
    Ldap(BlocklistLdap),
    Mqtt(BlocklistMqtt),
    Nfs(BlocklistNfs),
    Ntlm(BlocklistNtlm),
    Rdp(BlocklistRdp),
    Smb(BlocklistSmb),
    Smtp(BlocklistSmtp),
    Ssh(BlocklistSsh),
    Tls(BlocklistTls),
    Bootp(BlocklistBootp),
    Dhcp(BlocklistDhcp),
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
        locator: Option<&ip2location::DB>,
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
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => bootp_event.matches(locator, filter),
                RecordType::Conn(conn_event) => conn_event.matches(locator, filter),
                RecordType::DceRpc(dcerpc_event) => dcerpc_event.matches(locator, filter),
                RecordType::Dhcp(dhcp_event) => dhcp_event.matches(locator, filter),
                RecordType::Dns(dns_event) => dns_event.matches(locator, filter),
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
            Event::LockyRansomware(event) => event.matches(locator, filter),
            Event::SuspiciousTlsTraffic(event) => event.matches(locator, filter),
        }
    }

    fn address_pair(
        &self,
        locator: Option<&ip2location::DB>,
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
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(bootp_event.src_addr), Some(bootp_event.dst_addr));
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(conn_event.src_addr), Some(conn_event.dst_addr));
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(dcerpc_event.src_addr), Some(dcerpc_event.dst_addr));
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(dhcp_event.src_addr), Some(dhcp_event.dst_addr));
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        addr_pair = (Some(dns_event.src_addr), Some(dns_event.dst_addr));
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
            Event::LockyRansomware(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(locator, filter)?.0 {
                    addr_pair = (Some(event.src_addr), Some(event.dst_addr));
                }
            }
        }
        Ok(addr_pair)
    }

    fn kind(
        &self,
        locator: Option<&ip2location::DB>,
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
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(locator, filter)?.0 {
                        kind = Some(BLOCK_LIST);
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
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
            Event::LockyRansomware(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(LOCKY_RANSOMWARE);
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(locator, filter)?.0 {
                    kind = Some(SUSPICIOUS_TLS_TRAFFIC);
                }
            }
        }
        Ok(kind)
    }

    fn kind_and_category(&self) -> (EventKind, EventCategory) {
        match self {
            Event::DnsCovertChannel(e) => (EventKind::DnsCovertChannel, e.category()),
            Event::HttpThreat(e) => (EventKind::HttpThreat, e.category()),
            Event::RdpBruteForce(e) => (EventKind::RdpBruteForce, e.category()),
            Event::RepeatedHttpSessions(e) => (EventKind::RepeatedHttpSessions, e.category()),
            Event::TorConnection(e) => (EventKind::TorConnection, e.category()),
            Event::DomainGenerationAlgorithm(e) => {
                (EventKind::DomainGenerationAlgorithm, e.category())
            }
            Event::FtpBruteForce(e) => (EventKind::FtpBruteForce, e.category()),
            Event::FtpPlainText(e) => (EventKind::FtpPlainText, e.category()),
            Event::PortScan(e) => (EventKind::PortScan, e.category()),
            Event::MultiHostPortScan(e) => (EventKind::MultiHostPortScan, e.category()),
            Event::ExternalDdos(e) => (EventKind::ExternalDdos, e.category()),
            Event::NonBrowser(e) => (EventKind::NonBrowser, e.category()),
            Event::LdapBruteForce(e) => (EventKind::LdapBruteForce, e.category()),
            Event::LdapPlainText(e) => (EventKind::LdapPlainText, e.category()),
            Event::CryptocurrencyMiningPool(e) => {
                (EventKind::CryptocurrencyMiningPool, e.category())
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(e) => (EventKind::BlocklistBootp, e.category()),
                RecordType::Conn(e) => (EventKind::BlocklistConn, e.category()),
                RecordType::DceRpc(e) => (EventKind::BlocklistDceRpc, e.category()),
                RecordType::Dhcp(e) => (EventKind::BlocklistDhcp, e.category()),
                RecordType::Dns(e) => (EventKind::BlocklistDns, e.category()),
                RecordType::Ftp(e) => (EventKind::BlocklistFtp, e.category()),
                RecordType::Http(e) => (EventKind::BlocklistHttp, e.category()),
                RecordType::Kerberos(e) => (EventKind::BlocklistKerberos, e.category()),
                RecordType::Ldap(e) => (EventKind::BlocklistLdap, e.category()),
                RecordType::Mqtt(e) => (EventKind::BlocklistMqtt, e.category()),
                RecordType::Nfs(e) => (EventKind::BlocklistNfs, e.category()),
                RecordType::Ntlm(e) => (EventKind::BlocklistNtlm, e.category()),
                RecordType::Rdp(e) => (EventKind::BlocklistRdp, e.category()),
                RecordType::Smb(e) => (EventKind::BlocklistSmb, e.category()),
                RecordType::Smtp(e) => (EventKind::BlocklistSmtp, e.category()),
                RecordType::Ssh(e) => (EventKind::BlocklistSsh, e.category()),
                RecordType::Tls(e) => (EventKind::BlocklistTls, e.category()),
            },
            Event::WindowsThreat(e) => (EventKind::WindowsThreat, e.category()),
            Event::NetworkThreat(e) => (EventKind::NetworkThreat, e.category()),
            Event::ExtraThreat(e) => (EventKind::ExtraThreat, e.category()),
            Event::LockyRansomware(e) => (EventKind::LockyRansomware, e.category()),
            Event::SuspiciousTlsTraffic(e) => (EventKind::SuspiciousTlsTraffic, e.category()),
        }
    }

    // TODO: Need to implement country counting for `WindowsThreat`.
    // 1. for Network Connection: count country via ip
    // 2. for other Sysmon events: count the country by KR because the event does not have ip address.
    /// Counts the number of events per country.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_country(
        &self,
        counter: &mut HashMap<String, usize>,
        locator: Option<&ip2location::DB>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(locator, filter)?;

        let mut src_country = "ZZ".to_string();
        let mut dst_country = "ZZ".to_string();
        if let Some(locator) = locator {
            if let Some(src_addr) = addr_pair.0 {
                src_country = find_ip_country(locator, src_addr);
            }
            if let Some(dst_addr) = addr_pair.1 {
                dst_country = find_ip_country(locator, dst_addr);
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
        locator: Option<&ip2location::DB>,
        filter: &EventFilter,
    ) -> Result<()> {
        let mut category = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(locator, filter)?.0 {
                        category = Some(bootp_event.category());
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        category = Some(conn_event.category());
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        category = Some(dcerpc_event.category());
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(locator, filter)?.0 {
                        category = Some(dhcp_event.category());
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        category = Some(dns_event.category());
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        category = Some(ftp_event.category());
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        category = Some(http_event.category());
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        category = Some(kerberos_event.category());
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        category = Some(ldap_event.category());
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        category = Some(mqtt_event.category());
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        category = Some(nfs_event.category());
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        category = Some(ntlm_event.category());
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        category = Some(rdp_event.category());
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        category = Some(smb_event.category());
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        category = Some(smtp_event.category());
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        category = Some(ssh_event.category());
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        category = Some(tls_event.category());
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::LockyRansomware(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(locator, filter)?.0 {
                    category = Some(event.category());
                }
            }
        }

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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(locator, filter)?;
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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
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
        locator: Option<&ip2location::DB>,
        filter: &EventFilter,
    ) -> Result<()> {
        let mut level = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::TorConnection(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::PortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(locator, filter)?.0 {
                        level = Some(bootp_event.level());
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(locator, filter)?.0 {
                        level = Some(conn_event.level());
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(locator, filter)?.0 {
                        level = Some(dcerpc_event.level());
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(locator, filter)?.0 {
                        level = Some(dhcp_event.level());
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(locator, filter)?.0 {
                        level = Some(dns_event.level());
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(locator, filter)?.0 {
                        level = Some(ftp_event.level());
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(locator, filter)?.0 {
                        level = Some(http_event.level());
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(locator, filter)?.0 {
                        level = Some(kerberos_event.level());
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(locator, filter)?.0 {
                        level = Some(ldap_event.level());
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(locator, filter)?.0 {
                        level = Some(mqtt_event.level());
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(locator, filter)?.0 {
                        level = Some(nfs_event.level());
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(locator, filter)?.0 {
                        level = Some(ntlm_event.level());
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(locator, filter)?.0 {
                        level = Some(rdp_event.level());
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(locator, filter)?.0 {
                        level = Some(smb_event.level());
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(locator, filter)?.0 {
                        level = Some(smtp_event.level());
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(locator, filter)?.0 {
                        level = Some(ssh_event.level());
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(locator, filter)?.0 {
                        level = Some(tls_event.level());
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LockyRansomware(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(locator, filter)?.0 {
                    level = Some(event.level());
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
        locator: Option<&ip2location::DB>,
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
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    bootp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Conn(conn_event) => {
                    conn_event.triage_scores = Some(triage_scores);
                }
                RecordType::DceRpc(dcerpc_event) => {
                    dcerpc_event.triage_scores = Some(triage_scores);
                }
                RecordType::Dhcp(dhcp_event) => {
                    dhcp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Dns(dns_event) => {
                    dns_event.triage_scores = Some(triage_scores);
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
            Event::LockyRansomware(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::SuspiciousTlsTraffic(event) => {
                event.triage_scores = Some(triage_scores);
            }
        }
    }

    /// Generate syslog msgid and message body for RFC5424.
    #[must_use]
    pub fn syslog_message(&self) -> (String, String, String) {
        let (kind, _category) = self.kind_and_category();
        ("DETECT".to_string(), format!("{kind:?}"), format!("{self}"))
    }
}

fn find_network(ip: IpAddr, networks: &[Network]) -> Option<u32> {
    for net in networks {
        if net.networks.contains(ip) {
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
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
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
                &["http", "covert", "channel", "repeated", "http", "sessions"],
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
            moderate_kinds_by(kinds, &["external", "ddos", "dos"], "external ddos");
            moderate_kinds_by(kinds, &["port", "scan"], "port scan");
            moderate_kinds_by(
                kinds,
                &["non", "browser", "non-browser", "connection"],
                "non browser",
            );
            moderate_kinds_by(
                kinds,
                &["cryptocurrency", "mining", "pool", "network", "connection"],
                "cryptocurrency mining pool",
            );
            moderate_kinds_by(kinds, &["block", "list", "bootp"], "block list bootp");
            moderate_kinds_by(kinds, &["block", "list", "conn"], "block list conn");
            moderate_kinds_by(
                kinds,
                &["block", "list", "dcerpc", "dce/rpc"],
                "block list dcerpc",
            );
            moderate_kinds_by(kinds, &["block", "list", "dhcp"], "block list dhcp");
            moderate_kinds_by(kinds, &["block", "list", "dns"], "block list dns");
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
            moderate_kinds_by(kinds, &["locky", "ransomware"], "locky ransomware");
            moderate_kinds_by(
                kinds,
                &["suspicious", "tls", "traffic"],
                "suspicious tls traffic",
            );
        }
    }
}

fn moderate_kinds_by(kinds: &mut Vec<String>, patterns: &[&str], full_name: &str) {
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns)
        .expect("automatic build should not fail");
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

impl EventMessage {
    /// # Errors
    ///
    /// Returns an error if the deserialization of the event fields fails.
    pub fn syslog_rfc5424(&self) -> Result<(String, String, String)> {
        let msg = match self.kind {
            EventKind::DnsCovertChannel => bincode::deserialize::<DnsEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::HttpThreat => bincode::deserialize::<HttpThreatFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::RdpBruteForce => bincode::deserialize::<RdpBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::RepeatedHttpSessions => {
                bincode::deserialize::<RepeatedHttpSessionsFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::TorConnection => bincode::deserialize::<HttpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::DomainGenerationAlgorithm => bincode::deserialize::<DgaFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::FtpBruteForce => bincode::deserialize::<FtpBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::FtpPlainText => bincode::deserialize::<FtpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::PortScan => bincode::deserialize::<PortScanFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::MultiHostPortScan => {
                bincode::deserialize::<MultiHostPortScanFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::NonBrowser => bincode::deserialize::<HttpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LdapBruteForce => bincode::deserialize::<LdapBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LdapPlainText => bincode::deserialize::<LdapEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::ExternalDdos => bincode::deserialize::<ExternalDdosFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::CryptocurrencyMiningPool => {
                bincode::deserialize::<CryptocurrencyMiningPoolFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistBootp => bincode::deserialize::<BlocklistBootpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistConn => bincode::deserialize::<BlocklistConnFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistDceRpc => {
                bincode::deserialize::<BlocklistDceRpcFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistDhcp => bincode::deserialize::<BlocklistDhcpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistDns => bincode::deserialize::<BlocklistDnsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistFtp => bincode::deserialize::<FtpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistHttp => bincode::deserialize::<BlocklistHttpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistKerberos => {
                bincode::deserialize::<BlocklistKerberosFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistLdap => bincode::deserialize::<LdapEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistMqtt => bincode::deserialize::<BlocklistMqttFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistNfs => bincode::deserialize::<BlocklistNfsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistNtlm => bincode::deserialize::<BlocklistNtlmFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistRdp => bincode::deserialize::<BlocklistRdpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSmb => bincode::deserialize::<BlocklistSmbFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSmtp => bincode::deserialize::<BlocklistSmtpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSsh => bincode::deserialize::<BlocklistSshFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistTls => bincode::deserialize::<BlocklistTlsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::WindowsThreat => bincode::deserialize::<WindowsThreat>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::NetworkThreat => bincode::deserialize::<NetworkThreat>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::ExtraThreat => bincode::deserialize::<ExtraThreat>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LockyRansomware => bincode::deserialize::<DnsEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::SuspiciousTlsTraffic => {
                bincode::deserialize::<BlocklistTlsFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
        };

        match msg {
            Ok(msg) => Ok((
                "DETECT".to_string(),
                format!("{:?}", self.kind),
                format!(
                    "time={:?} event_kind=\"{:?}\" {msg}",
                    self.time.to_rfc3339(),
                    self.kind
                ),
            )),
            Err(e) => Err(anyhow::anyhow!(
                "failed to deserialize event fields: {e}. time={:?}, event_kind={:?}",
                self.time.to_rfc3339(),
                self.kind
            )),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventDb<'a> {
    inner: &'a rocksdb::OptimisticTransactionDB,
}

impl<'a> EventDb<'a> {
    #[must_use]
    pub fn new(inner: &'a rocksdb::OptimisticTransactionDB) -> EventDb<'a> {
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
        use anyhow::anyhow;
        let mut key = (i128::from(event.time.timestamp_nanos_opt().unwrap_or(i64::MAX)) << 64)
            | (event
                .kind
                .to_i128()
                .ok_or(anyhow!("`EventKind` exceeds i128::MAX"))?
                << 32);
        loop {
            let txn = self.inner.transaction();
            if txn
                .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
                .context("cannot read from event database")?
                .is_some()
            {
                let start = i128::from(rng().next_u32());
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
            }

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

impl Iterator for EventIterator<'_> {
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
                let Ok(fields) = bincode::deserialize::<HttpEventFields>(v.as_ref()) else {
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
                let Ok(fields) = bincode::deserialize::<FtpEventFields>(v.as_ref()) else {
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
                let Ok(fields) = bincode::deserialize::<HttpEventFields>(v.as_ref()) else {
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
                let Ok(fields) = bincode::deserialize::<LdapEventFields>(v.as_ref()) else {
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
            EventKind::BlocklistBootp => {
                let Ok(fields) = bincode::deserialize::<BlocklistBootpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(time, fields))),
                )))
            }
            EventKind::BlocklistConn => {
                let Ok(fields) = bincode::deserialize::<BlocklistConnFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Conn(BlocklistConn::new(time, fields))),
                )))
            }
            EventKind::BlocklistDceRpc => {
                let Ok(fields) = bincode::deserialize::<BlocklistDceRpcFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::DceRpc(BlocklistDceRpc::new(time, fields))),
                )))
            }
            EventKind::BlocklistDhcp => {
                let Ok(fields) = bincode::deserialize::<BlocklistDhcpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(time, fields))),
                )))
            }
            EventKind::BlocklistDns => {
                let Ok(fields) = bincode::deserialize::<BlocklistDnsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Dns(BlocklistDns::new(time, fields))),
                )))
            }
            EventKind::BlocklistFtp => {
                let Ok(fields) = bincode::deserialize::<FtpEventFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ftp(BlocklistFtp::new(time, fields))),
                )))
            }
            EventKind::BlocklistHttp => {
                let Ok(fields) = bincode::deserialize::<BlocklistHttpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Http(BlocklistHttp::new(time, fields))),
                )))
            }
            EventKind::BlocklistKerberos => {
                let Ok(fields) = bincode::deserialize::<BlocklistKerberosFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Kerberos(BlocklistKerberos::new(time, fields))),
                )))
            }
            EventKind::BlocklistLdap => {
                let Ok(fields) = bincode::deserialize::<LdapEventFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ldap(BlocklistLdap::new(time, fields))),
                )))
            }
            EventKind::BlocklistMqtt => {
                let Ok(fields) = bincode::deserialize::<BlocklistMqttFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Mqtt(BlocklistMqtt::new(time, fields))),
                )))
            }
            EventKind::BlocklistNfs => {
                let Ok(fields) = bincode::deserialize::<BlocklistNfsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Nfs(BlocklistNfs::new(time, fields))),
                )))
            }
            EventKind::BlocklistNtlm => {
                let Ok(fields) = bincode::deserialize::<BlocklistNtlmFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ntlm(BlocklistNtlm::new(time, fields))),
                )))
            }
            EventKind::BlocklistRdp => {
                let Ok(fields) = bincode::deserialize::<BlocklistRdpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Rdp(BlocklistRdp::new(time, fields))),
                )))
            }
            EventKind::BlocklistSmb => {
                let Ok(fields) = bincode::deserialize::<BlocklistSmbFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Smb(BlocklistSmb::new(time, fields))),
                )))
            }
            EventKind::BlocklistSmtp => {
                let Ok(fields) = bincode::deserialize::<BlocklistSmtpFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Smtp(BlocklistSmtp::new(time, fields))),
                )))
            }
            EventKind::BlocklistSsh => {
                let Ok(fields) = bincode::deserialize::<BlocklistSshFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ssh(BlocklistSsh::new(time, fields))),
                )))
            }
            EventKind::BlocklistTls => {
                let Ok(fields) = bincode::deserialize::<BlocklistTlsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Tls(BlocklistTls::new(time, fields))),
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
            EventKind::LockyRansomware => {
                let Ok(fields) = bincode::deserialize::<DnsEventFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LockyRansomware(LockyRansomware::new(time, fields)),
                )))
            }
            EventKind::SuspiciousTlsTraffic => {
                let Ok(fields) = bincode::deserialize::<BlocklistTlsFields>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::SuspiciousTlsTraffic(SuspiciousTlsTraffic::new(time, fields)),
                )))
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

#[must_use]
pub fn find_ip_country(locator: &ip2location::DB, addr: IpAddr) -> String {
    locator
        .ip_lookup(addr)
        .map(|r| get_record_country_short_name(&r))
        .ok()
        .flatten()
        .unwrap_or_else(|| "XX".to_string())
}

fn eq_ip_country(locator: &ip2location::DB, addr: IpAddr, country: [u8; 2]) -> bool {
    locator
        .ip_lookup(addr)
        .ok()
        .and_then(|r| get_record_country_short_name(&r))
        .is_some_and(|c| c.as_bytes() == country)
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
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        sync::Arc,
    };

    use chrono::{TimeZone, Utc};

    use crate::{
        BlocklistBootp, BlocklistBootpFields, BlocklistConnFields, BlocklistDceRpcFields,
        BlocklistDhcp, BlocklistDhcpFields, BlocklistDnsFields, BlocklistHttp, BlocklistHttpFields,
        BlocklistKerberosFields, BlocklistMqttFields, BlocklistNfsFields, BlocklistNtlmFields,
        BlocklistRdpFields, BlocklistSmbFields, BlocklistSmtpFields, BlocklistSshFields,
        BlocklistTlsFields, CryptocurrencyMiningPoolFields, DgaFields, DnsEventFields,
        DomainGenerationAlgorithm, Event, EventFilter, EventKind, EventMessage, ExternalDdos,
        ExternalDdosFields, ExtraThreat, FtpBruteForceFields, FtpEventFields, HttpEventFields,
        HttpThreat, HttpThreatFields, LdapBruteForceFields, LdapEventFields,
        MultiHostPortScanFields, NetworkThreat, PortScanFields, RdpBruteForceFields, RecordType,
        RepeatedHttpSessionsFields, Store, SuspiciousTlsTraffic, TriageScore, WindowsThreat,
        event::LOCKY_RANSOMWARE, types::EventCategory,
    };

    fn example_message(kind: EventKind, category: EventCategory) -> EventMessage {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
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
            category,
        };
        EventMessage {
            time: Utc::now(),
            kind,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn event_db_put() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        assert!(db.iter_forward().next().is_none());

        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
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
    async fn event_message() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        let msg = example_message(EventKind::LockyRansomware, EventCategory::Impact);
        db.put(&msg).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: None,
            kinds: Some(vec!["locky ransomware".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: Some(0.5),
            triage_policies: None,
        };
        assert_eq!(event.kind(None, &filter).unwrap(), Some(LOCKY_RANSOMWARE));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(LOCKY_RANSOMWARE), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::Impact), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn syslog_for_dga() {
        let fields = DgaFields {
            sensor: "collector1".to_string(),
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
        };
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::DomainGenerationAlgorithm,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="DomainGenerationAlgorithm" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" duration="1000" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" orig_filenames="a1,a2" orig_mime_types="" resp_filenames="" resp_mime_types="b1,b2" post_body="1234567890..." state="" confidence="0.8""#
        );

        let dga = DomainGenerationAlgorithm::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            fields,
        );
        let event = Event::DomainGenerationAlgorithm(dga);
        let dga_display = format!("{event}");
        assert_eq!(
            &dga_display,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="DomainGenerationAlgorithm" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" duration="1000" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" orig_filenames="a1,a2" orig_mime_types="" resp_filenames="" resp_mime_types="b1,b2" post_body="1234567890..." state="" confidence="0.8" triage_scores="""#
        );
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

            let msg = example_message(
                EventKind::DnsCovertChannel,
                EventCategory::CommandAndControl,
            );

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
            let msg = example_message(EventKind::LockyRansomware, EventCategory::Impact);
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
        assert!(
            backup
                .restore_from_backup(
                    db_dir.path().join("states.db"),
                    db_dir.path().join("states.db"),
                    &RestoreOptions::default(),
                    1,
                )
                .is_ok()
        );

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

    #[tokio::test]
    async fn syslog_for_httpthreat() {
        let fields = HttpThreatFields {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "collector1".to_string(),
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
        };
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="HttpThreat" category="Reconnaissance" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" duration="1000" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" orig_filenames="a1,a2" orig_mime_types="" resp_filenames="" resp_mime_types="b1,b2" post_body="1234567890..." state="" db_name="db" rule_id="12000" matched_to="match" cluster_id="1111" attack_kind="attack" confidence="0.8""#
        );

        let http_threat =
            HttpThreat::new(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(), fields);
        let event = Event::HttpThreat(http_threat);
        let http_threat_display = format!("{event}");
        assert!(http_threat_display.contains("post_body=\"1234567890...\""));
        assert!(http_threat_display.contains("confidence=\"0.8\""));
    }

    #[tokio::test]
    async fn syslog_for_nonbrowser() {
        let fields = HttpEventFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            session_end_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 10, 10).unwrap(),
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
            category: EventCategory::CommandAndControl,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="NonBrowser" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" session_end_time="1970-01-01T00:10:10+00:00" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" orig_filenames="a1,a2" orig_mime_types="" resp_filenames="" resp_mime_types="b1,b2" post_body="1234567890..." state="""#
        );

        let non_browser = Event::NonBrowser(crate::NonBrowser::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();
        assert!(non_browser.contains("post_body=\"1234567890...\""));
        assert!(non_browser.contains("state=\"\""));
    }

    #[tokio::test]
    async fn syslog_for_blocklist_http() {
        let fields = BlocklistHttpFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 80,
            proto: 6,
            last_time: 600,
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
            category: EventCategory::InitialAccess,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::BlocklistHttp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="BlocklistHttp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" last_time="600" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" orig_filenames="a1,a2" orig_mime_types="" resp_filenames="" resp_mime_types="b1,b2" post_body="1234567890..." state="""#
        );

        let blocklist_http = Event::Blocklist(RecordType::Http(BlocklistHttp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert!(blocklist_http.contains("post_body=\"1234567890...\""));
        assert!(blocklist_http.contains("resp_mime_types=\"b1,b2\""));
    }

    #[tokio::test]
    async fn syslog_for_lockyransomware() {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            session_end_time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            dst_port: 53,
            proto: 17,
            query: "locky.com".to_string(),
            answer: vec!["1.1.1.100".to_string()],
            trans_id: 1100,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: true,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![120; 5],
            confidence: 0.8,
            category: EventCategory::Impact,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LockyRansomware" category="Impact" sensor="collector1" session_end_time="1970-01-01T01:01:01+00:00" src_addr="127.0.0.3" src_port="10000" dst_addr="127.0.0.4" dst_port="53" proto="17" query="locky.com" answer="1.1.1.100" trans_id="1100" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="true" rd_flag="false" ra_flag="false" ttl="120,120,120,120,120" confidence="0.8""#
        );

        let locky_ransomware = Event::LockyRansomware(crate::LockyRansomware::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            fields,
        ))
        .to_string();
        assert!(locky_ransomware.contains("sensor=\"collector1\""));
        assert!(locky_ransomware.contains("query=\"locky.com\""));
        assert!(locky_ransomware.contains("ttl=\"120,120,120,120,120\""));
        assert!(locky_ransomware.contains("confidence=\"0.8\""));
        assert!(locky_ransomware.contains("triage_scores=\"\""));
    }

    #[tokio::test]
    async fn syslog_for_portscan() {
        let fields = PortScanFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_ports: vec![80, 443, 8000, 8080, 8888, 8443, 9000, 9001, 9002],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            proto: 6,
            category: EventCategory::Reconnaissance,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::PortScan,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="PortScan" category="Reconnaissance" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_ports="80,443,8000,8080,8888,8443,9000,9001,9002" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" proto="6""#
        );

        let port_scan = Event::PortScan(crate::PortScan::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();
        assert_eq!(
            &port_scan,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="PortScan" category="Reconnaissance" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_ports="80,443,8000,8080,8888,8443,9000,9001,9002" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" proto="6" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_multihostportscan() {
        let fields = MultiHostPortScanFields {
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::MultiHostPortScan,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="MultiHostPortScan" category="Reconnaissance" src_addr="127.0.0.1" dst_addrs="127.0.0.2,127.0.0.3" dst_port="80" proto="6" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00""#
        );

        let multi_host_port_scan = Event::MultiHostPortScan(crate::MultiHostPortScan::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();
        assert_eq!(
            &multi_host_port_scan,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="MultiHostPortScan" category="Reconnaissance" src_addr="127.0.0.1" dst_addrs="127.0.0.2,127.0.0.3" dst_port="80" proto="6" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_externalddos() {
        let fields = ExternalDdosFields {
            src_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            proto: 6,
            category: EventCategory::Impact,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::ExternalDdos,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExternalDdos" category="Impact" src_addrs="127.0.0.2,127.0.0.3" dst_addr="127.0.0.1" proto="6" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00""#
        );

        let external_ddos = Event::ExternalDdos(ExternalDdos::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();
        assert_eq!(
            &external_ddos,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExternalDdos" category="Impact" src_addrs="127.0.0.2,127.0.0.3" dst_addr="127.0.0.1" proto="6" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    fn blocklist_bootp_fields() -> BlocklistBootpFields {
        BlocklistBootpFields {
            sensor: "collector1".to_string(),
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

    #[tokio::test]
    async fn syslog_for_blocklist_bootp() {
        let fields = blocklist_bootp_fields();

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistBootp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="68" dst_addr="127.0.0.2" dst_port="67" proto="17" last_time="100" op="1" htype="2" hops="1" xid="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" chaddr="01:02:03:04:05:06" sname="server_name" file="boot_file_name""#,
        );
        let blocklist_bootp = Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_bootp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistBootp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="68" dst_addr="127.0.0.2" dst_port="67" proto="17" last_time="100" op="1" htype="2" hops="1" xid="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" chaddr="01:02:03:04:05:06" sname="server_name" file="boot_file_name" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_blocklist_bootp() {
        use super::{BLOCK_LIST, MEDIUM};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = blocklist_bootp_fields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["block list bootp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(None, &filter).unwrap(), Some(BLOCK_LIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(BLOCK_LIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_conn() {
        let fields = BlocklistConnFields {
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistConn" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" conn_state="SAF" duration="1000" service="http" orig_bytes="100" resp_bytes="100" orig_pkts="1" resp_pkts="1" orig_l2_bytes="122" resp_l2_bytes="122""#
        );

        let blocklist_conn = Event::Blocklist(RecordType::Conn(crate::BlocklistConn::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();
        assert_eq!(
            &blocklist_conn,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistConn" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="80" proto="6" conn_state="SAF" duration="1000" service="http" orig_bytes="100" resp_bytes="100" orig_pkts="1" resp_pkts="1" orig_l2_bytes="122" resp_l2_bytes="122" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_dcerpc() {
        let fields = BlocklistDceRpcFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistDceRpc,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDceRpc" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="135" proto="6" last_time="100" rtt="1" named_pipe="svcctl" endpoint="epmapper" operation="bind""#
        );

        let blocklist_dce_rpc = Event::Blocklist(RecordType::DceRpc(crate::BlocklistDceRpc::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();
        assert_eq!(
            &blocklist_dce_rpc,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDceRpc" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="135" proto="6" last_time="100" rtt="1" named_pipe="svcctl" endpoint="epmapper" operation="bind" triage_scores="""#
        );
    }

    fn blocklist_dhcp_fields() -> BlocklistDhcpFields {
        BlocklistDhcpFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 68,
            dst_addr: IpAddr::from_str("127.0.0.2").unwrap(),
            dst_port: 67,
            proto: 17,
            last_time: 100,
            msg_type: 1,
            ciaddr: IpAddr::from_str("127.0.0.5").unwrap(),
            yiaddr: IpAddr::from_str("127.0.0.6").unwrap(),
            siaddr: IpAddr::from_str("127.0.0.7").unwrap(),
            giaddr: IpAddr::from_str("127.0.0.8").unwrap(),
            subnet_mask: IpAddr::from_str("255.255.255.0").unwrap(),
            router: vec![IpAddr::from_str("127.0.0.1").unwrap()],
            domain_name_server: vec![IpAddr::from_str("127.0.0.1").unwrap()],
            req_ip_addr: IpAddr::from_str("127.0.0.100").unwrap(),
            lease_time: 100,
            server_id: IpAddr::from_str("127.0.0.1").unwrap(),
            param_req_list: vec![1, 2, 3],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: vec![4, 5, 6],
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            category: EventCategory::InitialAccess,
        }
    }

    #[tokio::test]
    async fn syslog_for_blocklist_dhcp() {
        let fields = blocklist_dhcp_fields();

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDhcp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="68" dst_addr="127.0.0.2" dst_port="67" proto="17" last_time="100" msg_type="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" subnet_mask="255.255.255.0" router="127.0.0.1" domain_name_server="127.0.0.1" req_ip_addr="127.0.0.100" lease_time="100" server_id="127.0.0.1" param_req_list="1,2,3" message="message" renewal_time="100" rebinding_time="200" class_id="04:05:06" client_id_type="1" client_id="07:08:09""#,
        );

        let blocklist_dhcp = Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_dhcp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDhcp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="68" dst_addr="127.0.0.2" dst_port="67" proto="17" last_time="100" msg_type="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" subnet_mask="255.255.255.0" router="127.0.0.1" domain_name_server="127.0.0.1" req_ip_addr="127.0.0.100" lease_time="100" server_id="127.0.0.1" param_req_list="1,2,3" message="message" renewal_time="100" rebinding_time="200" class_id="04:05:06" client_id_type="1" client_id="07:08:09" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_blocklist_dhcp() {
        use super::{BLOCK_LIST, MEDIUM};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = blocklist_dhcp_fields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["block list dhcp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(None, &filter).unwrap(), Some(BLOCK_LIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(BLOCK_LIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn syslog_for_dnscovertchannel() {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
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
            confidence: 0.9,
            category: EventCategory::CommandAndControl,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="DnsCovertChannel" category="CommandAndControl" sensor="collector1" session_end_time="1970-01-01T01:01:01+00:00" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" confidence="0.9""#
        );

        let triage_scores = vec![TriageScore {
            policy_id: 109,
            score: 0.9,
        }];
        let mut dns_covert_channel = Event::DnsCovertChannel(crate::DnsCovertChannel::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        ));
        dns_covert_channel.set_triage_scores(triage_scores);
        let dns_covert_channel = dns_covert_channel.to_string();

        assert_eq!(
            &dns_covert_channel,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="DnsCovertChannel" category="CommandAndControl" sensor="collector1" session_end_time="1970-01-01T01:01:01+00:00" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" confidence="0.9" triage_scores="109:0.90""#
        );
    }

    #[tokio::test]
    async fn syslog_for_cryptocurrencyminingpool() {
        let fields = CryptocurrencyMiningPoolFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::CryptocurrencyMiningPool,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="CryptocurrencyMiningPool" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" session_end_time="1970-01-01T01:01:01+00:00" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" coins="bitcoin,monero""#
        );

        let cryptocurrency_mining_pool =
            Event::CryptocurrencyMiningPool(crate::CryptocurrencyMiningPool::new(
                Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
                fields,
            ))
            .to_string();
        assert_eq!(
            &cryptocurrency_mining_pool,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="CryptocurrencyMiningPool" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" session_end_time="1970-01-01T01:01:01+00:00" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" coins="bitcoin,monero" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_dns() {
        let fields = BlocklistDnsFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistDns,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDns" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" last_time="100" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120""#
        );
        let blocklist_dns = Event::Blocklist(RecordType::Dns(crate::BlocklistDns::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();
        assert_eq!(
            &blocklist_dns,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDns" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="53" proto="17" last_time="100" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_ftpbruteforce() {
        let fields = FtpBruteForceFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 21,
            proto: 6,
            user_list: vec!["user1".to_string(), "user_2".to_string()],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 2).unwrap(),
            is_internal: true,
            category: EventCategory::CredentialAccess,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="FtpBruteForce" category="CredentialAccess" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_port="21" proto="6" user_list="user1,user_2" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" is_internal="true""#
        );

        let ftp_brute_force = Event::FtpBruteForce(crate::FtpBruteForce::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();

        assert_eq!(
            &ftp_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="FtpBruteForce" category="CredentialAccess" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_port="21" proto="6" user_list="user1,user_2" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" is_internal="true" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_ftpplaintext() {
        let fields = FtpEventFields {
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::FtpPlainText,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="FtpPlainText" category="LateralMovement" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="21" proto="6" last_time="100" user="user1" password="password" command="ls" reply_code="200" reply_msg="OK" data_passive="false" data_orig_addr="127.0.0.3" data_resp_addr="127.0.0.4" data_resp_port="10001" file="/etc/passwd" file_size="5000" file_id="123""#
        );

        let ftp_plain_text = Event::FtpPlainText(crate::FtpPlainText::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        ))
        .to_string();
        assert_eq!(
            &ftp_plain_text,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="FtpPlainText" category="LateralMovement" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="21" proto="6" last_time="100" user="user1" password="password" command="ls" reply_code="200" reply_msg="OK" data_passive="false" data_orig_addr="127.0.0.3" data_resp_addr="127.0.0.4" data_resp_port="10001" file="/etc/passwd" file_size="5000" file_id="123" triage_scores="""#
        );
    }

    fn ftpeventfields() -> FtpEventFields {
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
            category: EventCategory::InitialAccess,
        }
    }

    #[tokio::test]
    async fn syslog_for_blocklist_ftp() {
        let fields = ftpeventfields();

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistFtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistFtp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="21" proto="6" last_time="100" user="user1" password="password" command="ls" reply_code="200" reply_msg="OK" data_passive="false" data_orig_addr="127.0.0.3" data_resp_addr="127.0.0.4" data_resp_port="10001" file="/etc/passwd" file_size="5000" file_id="123""#
        );

        let blocklist_ftp = Event::Blocklist(RecordType::Ftp(crate::BlocklistFtp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_ftp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistFtp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="21" proto="6" last_time="100" user="user1" password="password" command="ls" reply_code="200" reply_msg="OK" data_passive="false" data_orig_addr="127.0.0.3" data_resp_addr="127.0.0.4" data_resp_port="10001" file="/etc/passwd" file_size="5000" file_id="123" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_blocklist_ftp() {
        use super::{BLOCK_LIST, MEDIUM};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = ftpeventfields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistFtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["block list ftp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: Some(0.5),
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(None, &filter).unwrap(), Some(BLOCK_LIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(BLOCK_LIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn syslog_for_repeatedhttpsessions() {
        let fields = RepeatedHttpSessionsFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 443,
            proto: 6,
            category: EventCategory::Exfiltration,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::RepeatedHttpSessions,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="RepeatedHttpSessions" category="Exfiltration" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6""#
        );
        let repeated_http_sessions = Event::RepeatedHttpSessions(crate::RepeatedHttpSessions::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();
        assert_eq!(
            &repeated_http_sessions,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="RepeatedHttpSessions" category="Exfiltration" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_kerberos() {
        let fields = BlocklistKerberosFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistKerberos,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistKerberos" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="88" proto="17" last_time="100" client_time="100" server_time="101" error_code="0" client_realm="EXAMPLE.COM" cname_type="1" client_name="user1" realm="EXAMPLE.COM" sname_type="1" service_name="krbtgt/EXAMPLE.COM""#
        );

        let blocklist_kerberos =
            Event::Blocklist(RecordType::Kerberos(crate::BlocklistKerberos::new(
                Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
                fields,
            )))
            .to_string();

        assert_eq!(
            &blocklist_kerberos,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistKerberos" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="88" proto="17" last_time="100" client_time="100" server_time="101" error_code="0" client_realm="EXAMPLE.COM" cname_type="1" client_name="user1" realm="EXAMPLE.COM" sname_type="1" service_name="krbtgt/EXAMPLE.COM" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_ldapbruteforce() {
        let fields = LdapBruteForceFields {
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::LdapBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LdapBruteForce" category="CredentialAccess" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_port="389" proto="6" user_pw_list="user1:pw1,user_2:pw2" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00""#
        );

        let ldap_brute_force = Event::LdapBruteForce(crate::LdapBruteForce::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();

        assert_eq!(
            &ldap_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LdapBruteForce" category="CredentialAccess" src_addr="127.0.0.1" dst_addr="127.0.0.2" dst_port="389" proto="6" user_pw_list="user1:pw1,user_2:pw2" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_ldapplaintext() {
        let fields = LdapEventFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::LdapPlainText,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="LdapPlainText" category="LateralMovement" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="389" proto="6" last_time="100" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument""#
        );

        let ldap_plain_text = Event::LdapPlainText(crate::LdapPlainText::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        ))
        .to_string();

        assert_eq!(
            &ldap_plain_text,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="LdapPlainText" category="LateralMovement" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="389" proto="6" last_time="100" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" triage_scores="""#
        );
    }

    fn ldapeventfields() -> LdapEventFields {
        LdapEventFields {
            sensor: "collector1".to_string(),
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
            category: EventCategory::InitialAccess,
        }
    }

    #[tokio::test]
    async fn syslog_for_blocklist_ldap() {
        let fields = ldapeventfields();

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistLdap,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistLdap" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="389" proto="6" last_time="100" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument""#
        );

        let blocklist_ldap = Event::Blocklist(RecordType::Ldap(crate::BlocklistLdap::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_ldap,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistLdap" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="389" proto="6" last_time="100" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_blocklist_ldap() {
        use super::{BLOCK_LIST, MEDIUM};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = ldapeventfields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistLdap,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["block list ldap".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: Some(0.5),
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(None, &filter).unwrap(), Some(BLOCK_LIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(BLOCK_LIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn syslog_for_extrathreat() {
        let fields = ExtraThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::ExtraThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExtraThreat" category="Reconnaissance" sensor="collector1" service="service" content="content" db_name="db_name" rule_id="1" matched_to="matched_to" cluster_id="1" attack_kind="attack_kind" confidence="0.9" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_mqtt() {
        let fields = BlocklistMqttFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistMqtt,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMqtt" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="1883" proto="6" last_time="100" protocol="mqtt" version="211" client_id="client1" connack_reason="0" subscribe="topic" suback_reason="error""#
        );

        let blocklist_mqtt = Event::Blocklist(RecordType::Mqtt(crate::BlocklistMqtt::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_mqtt,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMqtt" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="1883" proto="6" last_time="100" protocol="mqtt" version="211" client_id="client1" connack_reason="0" subscribe="topic" suback_reason="error" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_networkthreat() {
        let fields = NetworkThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::NetworkThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="NetworkThreat" category="Reconnaissance" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" service="http" last_time="100" content="content" db_name="db_name" rule_id="1" matched_to="matched_to" cluster_id="1" attack_kind="attack_kind" confidence="0.9" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_nfs() {
        let fields = BlocklistNfsFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 2049,
            proto: 6,
            last_time: 100,
            read_files: vec!["/etc/passwd".to_string()],
            write_files: vec!["/etc/shadow".to_string()],
            category: EventCategory::InitialAccess,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistNfs,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNfs" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="2049" proto="6" last_time="100" read_files="/etc/passwd" write_files="/etc/shadow""#
        );

        let blocklist_nfs = Event::Blocklist(RecordType::Nfs(crate::BlocklistNfs::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_nfs,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNfs" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="2049" proto="6" last_time="100" read_files="/etc/passwd" write_files="/etc/shadow" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_ntlm() {
        let fields = BlocklistNtlmFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistNtlm,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNtlm" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="445" proto="6" last_time="100" protocol="ntlm" username="user1" hostname="host1" domainname="domain1" success="true""#
        );

        let blocklist_ntlm = Event::Blocklist(RecordType::Ntlm(crate::BlocklistNtlm::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_ntlm,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNtlm" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="445" proto="6" last_time="100" protocol="ntlm" username="user1" hostname="host1" domainname="domain1" success="true" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_rdpbruteforce() {
        let fields = RdpBruteForceFields {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            last_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 10, 2).unwrap(),
            proto: 6,
            category: EventCategory::Discovery,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="RdpBruteForce" category="Discovery" src_addr="127.0.0.1" dst_addrs="127.0.0.2,127.0.0.3" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:10:02+00:00" proto="6""#
        );

        let rdp_brute_force = Event::RdpBruteForce(crate::RdpBruteForce::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();

        assert_eq!(
            &rdp_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="RdpBruteForce" category="Discovery" src_addr="127.0.0.1" dst_addrs="127.0.0.2,127.0.0.3" start_time="1970-01-01T00:01:01+00:00" last_time="1970-01-01T00:10:02+00:00" proto="6" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_rdp() {
        let fields = BlocklistRdpFields {
            sensor: "collector1".to_string(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 3389,
            proto: 6,
            last_time: 100,
            cookie: "cookie".to_string(),
            category: EventCategory::InitialAccess,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistRdp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRdp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="3389" proto="6" last_time="100" cookie="cookie""#
        );

        let blocklist_rdp = Event::Blocklist(RecordType::Rdp(crate::BlocklistRdp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_rdp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRdp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="3389" proto="6" last_time="100" cookie="cookie" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_smb() {
        let fields = BlocklistSmbFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistSmb,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmb" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="445" proto="6" last_time="100" command="1" path="path" service="service" file_name="file_name" file_size="100" resource_type="1" fid="1" create_time="100" access_time="200" write_time="300" change_time="400""#
        );

        let blocklist_smb = Event::Blocklist(RecordType::Smb(crate::BlocklistSmb::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_smb,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmb" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="445" proto="6" last_time="100" command="1" path="path" service="service" file_name="file_name" file_size="100" resource_type="1" fid="1" create_time="100" access_time="200" write_time="300" change_time="400" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_smtp() {
        let fields = BlocklistSmtpFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistSmtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmtp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="25" proto="6" last_time="100" mailfrom="mailfrom" date="date" from="from" to="to" subject="subject" agent="agent" state="state""#
        );

        let blocklist_smtp = Event::Blocklist(RecordType::Smtp(crate::BlocklistSmtp::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_smtp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmtp" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="25" proto="6" last_time="100" mailfrom="mailfrom" date="date" from="from" to="to" subject="subject" agent="agent" state="state" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_ssh() {
        let fields = BlocklistSshFields {
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistSsh,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSsh" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="22" proto="6" last_time="100" client="client" server="server" cipher_alg="cipher_alg" mac_alg="mac_alg" compression_alg="compression_alg" kex_alg="kex_alg" host_key_alg="host_key_alg" hassh_algorithms="hassh_algorithms" hassh="hassh" hassh_server_algorithms="hassh_server_algorithms" hassh_server="hassh_server" client_shka="client_shka" server_shka="server_shka""#
        );

        let blocklist_ssh = Event::Blocklist(RecordType::Ssh(crate::BlocklistSsh::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_ssh,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSsh" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="22" proto="6" last_time="100" client="client" server="server" cipher_alg="cipher_alg" mac_alg="mac_alg" compression_alg="compression_alg" kex_alg="kex_alg" host_key_alg="host_key_alg" hassh_algorithms="hassh_algorithms" hassh="hassh" hassh_server_algorithms="hassh_server_algorithms" hassh_server="hassh_server" client_shka="client_shka" server_shka="server_shka" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn syslog_for_windowsthreat() {
        let fields = WindowsThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "collector1".to_string(),
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
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            kind: EventKind::WindowsThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            "time=\"1970-01-01T00:01:01+00:00\" event_kind=\"WindowsThreat\" category=\"Impact\" sensor=\"collector1\" service=\"notepad\" agent_name=\"win64\" agent_id=\"e7e2386a-5485-4da9-b388-b3e50ee7cbb0\" process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\" process_id=\"2972\" image=\"C:\\Users\\vboxuser\\Desktop\\mal_bazaar\\ransomware\\918504.exe\" user=\"WIN64\\vboxuser\" content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\" db_name=\"db\" rule_id=\"100\" matched_to=\"match\" cluster_id=\"900\" attack_kind=\"Ransomware_Alcatraz\" confidence=\"0.9\" triage_scores=\"\""
        );
        assert!(syslog_message.contains("user=\"WIN64\\vboxuser\""));
        assert!(
            syslog_message
                .contains("content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\"")
        );

        let windows_threat = Event::WindowsThreat(fields).to_string();
        assert_eq!(
            &windows_threat,
            "time=\"1970-01-01T00:01:01+00:00\" event_kind=\"WindowsThreat\" category=\"Impact\" sensor=\"collector1\" service=\"notepad\" agent_name=\"win64\" agent_id=\"e7e2386a-5485-4da9-b388-b3e50ee7cbb0\" process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\" process_id=\"2972\" image=\"C:\\Users\\vboxuser\\Desktop\\mal_bazaar\\ransomware\\918504.exe\" user=\"WIN64\\vboxuser\" content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\" db_name=\"db\" rule_id=\"100\" matched_to=\"match\" cluster_id=\"900\" attack_kind=\"Ransomware_Alcatraz\" confidence=\"0.9\" triage_scores=\"\""
        );
        assert!(windows_threat.contains("process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\""));
        assert!(
            windows_threat
                .contains(r#"image="C:\Users\vboxuser\Desktop\mal_bazaar\ransomware\918504.exe""#)
        );
    }

    #[tokio::test]
    async fn syslog_for_blocklist_tls() {
        let fields = BlocklistTlsFields {
            sensor: "collector1".to_string(),
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
            last_alert: 1,
            confidence: 0.9,
            category: EventCategory::InitialAccess,
        };

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::BlocklistTls,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistTls" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" last_time="100" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9""#
        );

        let blocklist_tls = Event::Blocklist(RecordType::Tls(crate::BlocklistTls::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            fields,
        )))
        .to_string();

        assert_eq!(
            &blocklist_tls,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistTls" category="InitialAccess" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" last_time="100" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9" triage_scores="""#
        );
    }

    fn httpeventfields() -> HttpEventFields {
        HttpEventFields {
            sensor: "collector1".to_string(),
            session_end_time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 10000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst_port: 443,
            proto: 6,
            method: "GET".to_string(),
            host: "host".to_string(),
            uri: "uri".to_string(),
            referer: "referer".to_string(),
            version: "version".to_string(),
            user_agent: "user_agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            orig_filenames: vec!["filename".to_string()],
            orig_mime_types: vec!["mime_type".to_string()],
            resp_filenames: vec!["filename".to_string()],
            resp_mime_types: vec!["mime_type".to_string()],
            post_body: "post_body".as_bytes().to_vec(),
            state: "state".to_string(),
            category: EventCategory::CommandAndControl,
        }
    }

    #[tokio::test]
    async fn syslog_for_torconnection() {
        let fields = httpeventfields();

        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="TorConnection" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" session_end_time="1970-01-01T01:01:01+00:00" method="GET" host="host" uri="uri" referer="referer" version="version" user_agent="user_agent" request_len="100" response_len="200" status_code="200" status_msg="OK" username="user" password="password" cookie="cookie" content_encoding="content_encoding" content_type="content_type" cache_control="cache_control" orig_filenames="filename" orig_mime_types="mime_type" resp_filenames="filename" resp_mime_types="mime_type" post_body="post_body" state="state""#
        );

        let tor_connection = Event::TorConnection(crate::TorConnection::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            &fields,
        ))
        .to_string();

        assert_eq!(
            &tor_connection,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="TorConnection" category="CommandAndControl" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" session_end_time="1970-01-01T01:01:01+00:00" method="GET" host="host" uri="uri" referer="referer" version="version" user_agent="user_agent" request_len="100" response_len="200" status_code="200" status_msg="OK" username="user" password="password" cookie="cookie" content_encoding="content_encoding" content_type="content_type" cache_control="cache_control" orig_filenames="filename" orig_mime_types="mime_type" resp_filenames="filename" resp_mime_types="mime_type" post_body="post_body" state="state" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_torconnection() {
        use super::{MEDIUM, TOR_CONNECTION};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = httpeventfields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["tor exit nodes".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: Some(0.5),
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(None, &filter).unwrap(), Some(TOR_CONNECTION));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(TOR_CONNECTION), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::CommandAndControl), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    fn blocklist_tls_fields() -> BlocklistTlsFields {
        BlocklistTlsFields {
            sensor: "collector1".to_string(),
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
            last_alert: 1,
            confidence: 0.9,
            category: EventCategory::Unknown,
        }
    }

    #[tokio::test]
    async fn syslog_for_suspicious_tls_traffic() {
        use super::common::Match;

        let fields = blocklist_tls_fields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="SuspiciousTlsTraffic" category="Unknown" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" last_time="100" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9""#
        );

        let suspicious_tls_traffic =
            SuspiciousTlsTraffic::new(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(), fields);
        assert_eq!(
            suspicious_tls_traffic.src_addrs(),
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );
        assert_eq!(
            suspicious_tls_traffic.dst_addrs(),
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]
        );
        assert_eq!(suspicious_tls_traffic.category(), EventCategory::Unknown);
        assert_eq!(suspicious_tls_traffic.src_port(), 10000);
        assert_eq!(suspicious_tls_traffic.dst_port(), 443);
        assert_eq!(suspicious_tls_traffic.proto(), 6);
        let event = Event::SuspiciousTlsTraffic(suspicious_tls_traffic);
        let blocklist_tls = event.to_string();

        assert_eq!(
            &blocklist_tls,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="SuspiciousTlsTraffic" category="Unknown" sensor="collector1" src_addr="127.0.0.1" src_port="10000" dst_addr="127.0.0.2" dst_port="443" proto="6" last_time="100" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9" triage_scores="""#
        );
    }

    #[tokio::test]
    async fn event_suspicious_tls_traffic() {
        use super::{MEDIUM, SUSPICIOUS_TLS_TRAFFIC};

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let fields = blocklist_tls_fields();
        let message = EventMessage {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![MEDIUM]),
            kinds: Some(vec!["suspicious tls traffic".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence: Some(0.5),
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(None, &filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(
            event.kind(None, &filter).unwrap(),
            Some(SUSPICIOUS_TLS_TRAFFIC)
        );
        let mut counter = HashMap::new();
        event.count_level(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(SUSPICIOUS_TLS_TRAFFIC), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, None, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::Unknown), Some(&1));

        let mut counter = HashMap::new();
        event
            .count_ip_address_pair(&mut counter, None, &filter)
            .unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }
}
