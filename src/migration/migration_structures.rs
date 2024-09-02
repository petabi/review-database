use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use chrono::{serde::ts_nanoseconds, DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::{
    BlockListConnFields, BlockListDnsFields, BlockListHttpFields, BlockListKerberosFields,
    BlockListNtlmFields, BlockListRdpFields, BlockListSmtpFields, BlockListSshFields,
    BlockListTlsFields, CryptocurrencyMiningPoolFields, DgaFields, DnsEventFields, EventCategory,
    ExternalDdosFields, FtpBruteForceFields, FtpEventFields, HttpEventFields, HttpThreatFields,
    LdapBruteForceFields, LdapEventFields, MultiHostPortScanFields, NetworkThreat, PortScanFields,
    RdpBruteForceFields, RepeatedHttpSessionsFields, TriageScore, WindowsThreat,
};

#[derive(Deserialize, Serialize)]
pub struct BlockListConnBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl From<BlockListConnBeforeV29> for BlockListConnBeforeV30 {
    fn from(input: BlockListConnBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            conn_state: String::new(),
            duration: input.duration,
            service: input.service,
            orig_bytes: input.orig_bytes,
            resp_bytes: input.resp_bytes,
            orig_pkts: input.orig_pkts,
            resp_pkts: input.resp_pkts,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListConnBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
}

impl From<BlockListConnBeforeV30> for BlockListConnFields {
    fn from(input: BlockListConnBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            conn_state: input.conn_state,
            duration: input.duration,
            service: input.service,
            orig_bytes: input.orig_bytes,
            resp_bytes: input.resp_bytes,
            orig_pkts: input.orig_pkts,
            resp_pkts: input.resp_pkts,
            orig_l2_bytes: input.orig_l2_bytes,
            resp_l2_bytes: input.resp_l2_bytes,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatBeforeV29 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
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
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
}

impl From<HttpThreatBeforeV29> for HttpThreatBeforeV30 {
    fn from(input: HttpThreatBeforeV29) -> Self {
        Self {
            time: input.time,
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            duration: input.duration,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: String::new(),
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: input.cluster_id,
            attack_kind: input.attack_kind,
            confidence: input.confidence,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatBeforeV30 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
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
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
}

impl From<HttpThreatBeforeV30> for HttpThreatFields {
    fn from(input: HttpThreatBeforeV30) -> Self {
        Self {
            time: input.time,
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            duration: input.duration,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: input.post_body,
            state: input.state,
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: input.cluster_id,
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            category: EventCategory::Reconnaissance,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct DgaBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
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
    pub confidence: f32,
}

impl From<DgaBeforeV29> for DgaBeforeV30 {
    fn from(input: DgaBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            duration: input.duration,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: String::new(),
            confidence: input.confidence,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct DgaBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub duration: i64,
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
}

impl From<DgaBeforeV30> for DgaFields {
    fn from(input: DgaBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            duration: input.duration,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referer: input.referer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: input.post_body,
            state: input.state,
            confidence: input.confidence,
            category: EventCategory::CommandAndControl,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct NonBrowserBeforeV29 {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
}

impl From<NonBrowserBeforeV29> for NonBrowserBeforeV30 {
    fn from(input: NonBrowserBeforeV29) -> Self {
        Self {
            source: input.source,
            session_end_time: input.session_end_time,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: String::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct NonBrowserBeforeV30 {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
}

impl From<NonBrowserBeforeV30> for HttpEventFields {
    fn from(input: NonBrowserBeforeV30) -> Self {
        Self {
            source: input.source,
            session_end_time: input.session_end_time,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: input.post_body,
            state: input.state,
            category: EventCategory::CommandAndControl,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct BlockListDnsBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
}

impl From<BlockListDnsBeforeV30> for BlockListDnsFields {
    fn from(input: BlockListDnsBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            query: input.query,
            answer: input.answer,
            trans_id: input.trans_id,
            rtt: input.rtt,
            qclass: input.qclass,
            qtype: input.qtype,
            rcode: input.rcode,
            aa_flag: input.aa_flag,
            tc_flag: input.tc_flag,
            rd_flag: input.rd_flag,
            ra_flag: input.ra_flag,
            ttl: input.ttl,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListFtpBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

impl From<BlockListFtpBeforeV30> for FtpEventFields {
    fn from(input: BlockListFtpBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            user: input.user,
            password: input.password,
            command: input.command,
            reply_code: input.reply_code,
            reply_msg: input.reply_msg,
            data_passive: input.data_passive,
            data_orig_addr: input.data_orig_addr,
            data_resp_addr: input.data_resp_addr,
            data_resp_port: input.data_resp_port,
            file: input.file,
            file_size: input.file_size,
            file_id: input.file_id,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListHttpBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
}

impl From<BlockListHttpBeforeV29> for BlockListHttpBeforeV30 {
    fn from(input: BlockListHttpBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: Vec::new(),
            state: String::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListHttpBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
}

impl From<BlockListHttpBeforeV30> for BlockListHttpFields {
    fn from(input: BlockListHttpBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: input.orig_filenames,
            orig_mime_types: input.orig_mime_types,
            resp_filenames: input.resp_filenames,
            resp_mime_types: input.resp_mime_types,
            post_body: input.post_body,
            state: input.state,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListKerberosBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
}

impl From<BlockListKerberosBeforeV30> for BlockListKerberosFields {
    fn from(input: BlockListKerberosBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            client_time: input.client_time,
            server_time: input.server_time,
            error_code: input.error_code,
            client_realm: input.client_realm,
            cname_type: input.cname_type,
            client_name: input.client_name,
            realm: input.realm,
            sname_type: input.sname_type,
            service_name: input.service_name,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlockListLdapBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
}

impl From<BlockListLdapBeforeV30> for LdapEventFields {
    fn from(input: BlockListLdapBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            message_id: input.message_id,
            version: input.version,
            opcode: input.opcode,
            result: input.result,
            diagnostic_message: input.diagnostic_message,
            object: input.object,
            argument: input.argument,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListNtlmBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub server_nb_computer_name: String,
    pub server_dns_computer_name: String,
    pub server_tree_name: String,
    pub success: String,
}

impl From<BlockListNtlmBeforeV29> for BlockListNtlmBeforeV30 {
    fn from(input: BlockListNtlmBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            protocol: String::new(),
            username: input.username,
            hostname: input.hostname,
            domainname: input.domainname,
            success: input.success,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListNtlmBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
}

impl From<BlockListNtlmBeforeV30> for BlockListNtlmFields {
    fn from(input: BlockListNtlmBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            protocol: input.protocol,
            username: input.username,
            hostname: input.hostname,
            domainname: input.domainname,
            success: input.success,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListRdpBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub cookie: String,
}

impl From<BlockListRdpBeforeV30> for BlockListRdpFields {
    fn from(input: BlockListRdpBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            cookie: input.cookie,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSmtpBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
}

impl From<BlockListSmtpBeforeV29> for BlockListSmtpBeforeV30 {
    fn from(input: BlockListSmtpBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            mailfrom: input.mailfrom,
            date: input.date,
            from: input.from,
            to: input.to,
            subject: input.subject,
            agent: input.agent,
            state: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSmtpBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
}

impl From<BlockListSmtpBeforeV30> for BlockListSmtpFields {
    fn from(input: BlockListSmtpBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            mailfrom: input.mailfrom,
            date: input.date,
            from: input.from,
            to: input.to,
            subject: input.subject,
            agent: input.agent,
            state: input.state,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSshBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub version: i64,
    pub auth_success: String,
    pub auth_attempts: i64,
    pub direction: String,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub host_key: String,
}

impl From<BlockListSshBeforeV29> for BlockListSshBeforeV30 {
    fn from(input: BlockListSshBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            client: input.client,
            server: input.server,
            cipher_alg: input.cipher_alg,
            mac_alg: input.mac_alg,
            compression_alg: input.compression_alg,
            kex_alg: input.kex_alg,
            host_key_alg: input.host_key_alg,
            hassh_algorithms: String::new(),
            hassh: String::new(),
            hassh_server_algorithms: String::new(),
            hassh_server: String::new(),
            client_shka: String::new(),
            server_shka: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListSshBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
}

impl From<BlockListSshBeforeV30> for BlockListSshFields {
    fn from(input: BlockListSshBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            client: input.client,
            server: input.server,
            cipher_alg: input.cipher_alg,
            mac_alg: input.mac_alg,
            compression_alg: input.compression_alg,
            kex_alg: input.kex_alg,
            host_key_alg: input.host_key_alg,
            hassh_algorithms: input.hassh_algorithms,
            hassh: input.hassh,
            hassh_server_algorithms: input.hassh_server_algorithms,
            hassh_server: input.hassh_server,
            client_shka: input.client_shka,
            server_shka: input.server_shka,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListTlsBeforeV29 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub cipher: u16,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
}

impl From<BlockListTlsBeforeV29> for BlockListTlsBeforeV30 {
    fn from(input: BlockListTlsBeforeV29) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            server_name: input.server_name,
            alpn_protocol: input.alpn_protocol,
            ja3: input.ja3,
            version: input.version,
            client_cipher_suites: Vec::new(),
            client_extensions: Vec::new(),
            cipher: input.cipher,
            extensions: Vec::new(),
            ja3s: input.ja3s,
            serial: input.serial,
            subject_country: input.subject_country,
            subject_org_name: input.subject_org_name,
            subject_common_name: input.subject_common_name,
            validity_not_before: input.validity_not_before,
            validity_not_after: input.validity_not_after,
            subject_alt_name: input.subject_alt_name,
            issuer_country: input.issuer_country,
            issuer_org_name: input.issuer_org_name,
            issuer_org_unit_name: input.issuer_org_unit_name,
            issuer_common_name: input.issuer_common_name,
            last_alert: input.last_alert,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockListTlsBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
}

impl From<BlockListTlsBeforeV30> for BlockListTlsFields {
    fn from(input: BlockListTlsBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            server_name: input.server_name,
            alpn_protocol: input.alpn_protocol,
            ja3: input.ja3,
            version: input.version,
            client_cipher_suites: input.client_cipher_suites,
            client_extensions: input.client_extensions,
            cipher: input.cipher,
            extensions: input.extensions,
            ja3s: input.ja3s,
            serial: input.serial,
            subject_country: input.subject_country,
            subject_org_name: input.subject_org_name,
            subject_common_name: input.subject_common_name,
            validity_not_before: input.validity_not_before,
            validity_not_after: input.validity_not_after,
            subject_alt_name: input.subject_alt_name,
            issuer_country: input.issuer_country,
            issuer_org_name: input.issuer_org_name,
            issuer_org_unit_name: input.issuer_org_unit_name,
            issuer_common_name: input.issuer_common_name,
            last_alert: input.last_alert,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CryptocurrencyMiningPoolBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
}

impl From<CryptocurrencyMiningPoolBeforeV30> for CryptocurrencyMiningPoolFields {
    fn from(input: CryptocurrencyMiningPoolBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            session_end_time: input.session_end_time,
            query: input.query,
            answer: input.answer,
            trans_id: input.trans_id,
            rtt: input.rtt,
            qclass: input.qclass,
            qtype: input.qtype,
            rcode: input.rcode,
            aa_flag: input.aa_flag,
            tc_flag: input.tc_flag,
            rd_flag: input.rd_flag,
            ra_flag: input.ra_flag,
            ttl: input.ttl,
            coins: input.coins,
            category: EventCategory::CommandAndControl,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DnsCovertChannelBeforeV30 {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
}

impl From<DnsCovertChannelBeforeV30> for DnsEventFields {
    fn from(input: DnsCovertChannelBeforeV30) -> Self {
        Self {
            source: input.source,
            session_end_time: input.session_end_time,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            query: input.query,
            answer: input.answer,
            trans_id: input.trans_id,
            rtt: input.rtt,
            qclass: input.qclass,
            qtype: input.qtype,
            rcode: input.rcode,
            aa_flag: input.aa_flag,
            tc_flag: input.tc_flag,
            rd_flag: input.rd_flag,
            ra_flag: input.ra_flag,
            ttl: input.ttl,
            confidence: input.confidence,
            category: EventCategory::CommandAndControl,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExternalDdosBeforeV30 {
    pub src_addrs: Vec<IpAddr>,
    pub dst_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl From<ExternalDdosBeforeV30> for ExternalDdosFields {
    fn from(input: ExternalDdosBeforeV30) -> Self {
        Self {
            src_addrs: input.src_addrs,
            dst_addr: input.dst_addr,
            proto: input.proto,
            start_time: input.start_time,
            last_time: input.last_time,
            category: EventCategory::Impact,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceBeforeV30 {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub is_internal: bool,
}

impl From<FtpBruteForceBeforeV30> for FtpBruteForceFields {
    fn from(input: FtpBruteForceBeforeV30) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            user_list: input.user_list,
            start_time: input.start_time,
            last_time: input.last_time,
            is_internal: input.is_internal,
            category: EventCategory::CredentialAccess,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FtpPlainTextBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

impl From<FtpPlainTextBeforeV30> for FtpEventFields {
    fn from(input: FtpPlainTextBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            user: input.user,
            password: input.password,
            command: input.command,
            reply_code: input.reply_code,
            reply_msg: input.reply_msg,
            data_passive: input.data_passive,
            data_orig_addr: input.data_orig_addr,
            data_resp_addr: input.data_resp_addr,
            data_resp_port: input.data_resp_port,
            file: input.file,
            file_size: input.file_size,
            file_id: input.file_id,
            category: EventCategory::LateralMovement,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForceBeforeV30 {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl From<LdapBruteForceBeforeV30> for LdapBruteForceFields {
    fn from(input: LdapBruteForceBeforeV30) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            user_pw_list: input.user_pw_list,
            start_time: input.start_time,
            last_time: input.last_time,
            category: EventCategory::CredentialAccess,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct LdapPlainTextBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
}

impl From<LdapPlainTextBeforeV30> for LdapEventFields {
    fn from(input: LdapPlainTextBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            last_time: input.last_time,
            message_id: input.message_id,
            version: input.version,
            opcode: input.opcode,
            result: input.result,
            diagnostic_message: input.diagnostic_message,
            object: input.object,
            argument: input.argument,
            category: EventCategory::LateralMovement,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanBeforeV30 {
    pub src_addr: IpAddr,
    pub dst_port: u16,
    pub dst_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
}

impl From<MultiHostPortScanBeforeV30> for MultiHostPortScanFields {
    fn from(input: MultiHostPortScanBeforeV30) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_port: input.dst_port,
            dst_addrs: input.dst_addrs,
            proto: input.proto,
            start_time: input.start_time,
            last_time: input.last_time,
            category: EventCategory::Reconnaissance,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NetworkThreatBeforeV30 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub service: String,
    pub last_time: i64,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl From<NetworkThreatBeforeV30> for NetworkThreat {
    fn from(input: NetworkThreatBeforeV30) -> Self {
        Self {
            time: input.time,
            source: input.source,
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            service: input.service,
            last_time: input.last_time,
            content: input.content,
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: input.cluster_id,
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            triage_scores: input.triage_scores,
            category: EventCategory::Reconnaissance,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForceBeforeV30 {
    pub src_addr: IpAddr,
    pub dst_addrs: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
}

impl From<RdpBruteForceBeforeV30> for RdpBruteForceFields {
    fn from(input: RdpBruteForceBeforeV30) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_addrs: input.dst_addrs,
            start_time: input.start_time,
            last_time: input.last_time,
            proto: input.proto,
            category: EventCategory::Discovery,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessionsBeforeV30 {
    pub source: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}

impl From<RepeatedHttpSessionsBeforeV30> for RepeatedHttpSessionsFields {
    fn from(input: RepeatedHttpSessionsBeforeV30) -> Self {
        Self {
            source: input.source,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            category: EventCategory::Exfiltration,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PortScanBeforeV30 {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub proto: u8,
}

impl From<PortScanBeforeV30> for PortScanFields {
    fn from(input: PortScanBeforeV30) -> Self {
        Self {
            src_addr: input.src_addr,
            dst_addr: input.dst_addr,
            dst_ports: input.dst_ports,
            start_time: input.start_time,
            last_time: input.last_time,
            proto: input.proto,
            category: EventCategory::Reconnaissance,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct TorConnectionBeforeV30 {
    pub source: String,
    #[serde(with = "ts_nanoseconds")]
    pub session_end_time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
}

impl From<TorConnectionBeforeV30> for HttpEventFields {
    fn from(input: TorConnectionBeforeV30) -> Self {
        Self {
            source: input.source,
            session_end_time: input.session_end_time,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            method: input.method,
            host: input.host,
            uri: input.uri,
            referrer: input.referrer,
            version: input.version,
            user_agent: input.user_agent,
            request_len: input.request_len,
            response_len: input.response_len,
            status_code: input.status_code,
            status_msg: input.status_msg,
            username: input.username,
            password: input.password,
            cookie: input.cookie,
            content_encoding: input.content_encoding,
            content_type: input.content_type,
            cache_control: input.cache_control,
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: String::new(),
            category: EventCategory::CommandAndControl,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct WindowsThreatBeforeV30 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub source: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl From<WindowsThreatBeforeV30> for WindowsThreat {
    fn from(input: WindowsThreatBeforeV30) -> Self {
        Self {
            time: input.time,
            source: input.source,
            service: input.service,
            agent_name: input.agent_name,
            agent_id: input.agent_id,
            process_guid: input.process_guid,
            process_id: input.process_id,
            image: input.image,
            user: input.user,
            content: input.content,
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: input.cluster_id,
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            triage_scores: input.triage_scores,
            category: EventCategory::Impact,
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq)]
pub struct PigletConfig {
    pub dpdk_args: String,

    pub dpdk_input: Vec<String>,
    pub dpdk_output: Vec<String>,

    pub src_mac: String,
    pub dst_mac: String,

    pub log_dir: String,
    pub dump_dir: String,

    pub dump_items: Option<Vec<DumpItem>>,
    pub dump_http_content_types: Option<Vec<DumpHttpContentType>>,

    pub giganto_ingest_srv_addr: SocketAddr,
    pub giganto_name: String,

    pub pcap_max_size: u32,
}

#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DumpItem {
    Pcap,
    Eml,
    Ftp,
    Http,
}

#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DumpHttpContentType {
    Office,
    Exe,
    Pdf,
    Vbs,
    Txt,
}

#[derive(Deserialize, Serialize, PartialEq)]
pub struct HogConfig {
    pub active_protocols: Option<Vec<ProtocolForHog>>,
    pub active_sources: Option<Vec<String>>,

    pub giganto_publish_srv_addr: Option<SocketAddr>,

    pub cryptocurrency_mining_pool: String,

    pub log_dir: String,
    pub export_dir: String,

    pub services_path: String,
}

#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolForHog {
    Conn,
    Dns,
    Rdp,
    Http,
}

#[derive(Deserialize, Serialize, PartialEq)]
pub struct GigantoConfig {
    pub ingest_srv_addr: SocketAddr,
    pub publish_srv_addr: SocketAddr,
    pub graphql_srv_addr: SocketAddr,

    pub data_dir: String,
    pub log_dir: String,
    pub export_dir: String,

    #[serde(with = "humantime_serde")]
    pub retention: Duration,

    pub max_open_files: i32,
    pub max_mb_of_level_base: u64,
    pub num_of_thread: i32,
    pub max_sub_compactions: u32,

    pub ack_transmission: u16,
}
