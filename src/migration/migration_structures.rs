use std::net::IpAddr;

use chrono::{serde::ts_nanoseconds, DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    event::{DgaFields, HttpThreatFields, NonBrowserFields},
    BlockListConnFields, BlockListHttpFields, BlockListNtlmFields, BlockListSmtpFields,
    BlockListSshFields, BlockListTlsFields,
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

impl From<BlockListConnBeforeV29> for BlockListConnFields {
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

impl From<HttpThreatBeforeV29> for HttpThreatFields {
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

impl From<DgaBeforeV29> for DgaFields {
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

impl From<NonBrowserBeforeV29> for NonBrowserFields {
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

#[derive(Debug, Deserialize, Serialize)]
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

impl From<BlockListHttpBeforeV29> for BlockListHttpFields {
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
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
            post_body: Vec::new(),
            state: String::new(),
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

impl From<BlockListNtlmBeforeV29> for BlockListNtlmFields {
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

impl From<BlockListSmtpBeforeV29> for BlockListSmtpFields {
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

impl From<BlockListSshBeforeV29> for BlockListSshFields {
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

impl From<BlockListTlsBeforeV29> for BlockListTlsFields {
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
