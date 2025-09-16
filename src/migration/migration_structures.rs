use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::{
    Agent, EventCategory, ExternalServiceConfig, ExternalServiceStatus, Indexable, NodeProfile,
    Role, Tidb, TidbKind, TidbRule,
    account::{PasswordHashAlgorithm, SaltedPassword},
    event::{
        BlocklistTlsFields, ExtraThreat, FilterEndpoint, FlowKind, HttpThreatFieldsV0_34,
        LearningMethod, NetworkThreat, TriageScore, WindowsThreat,
    },
    tables::InnerNode,
    types::Account,
};

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatV0_33 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
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
    pub category: EventCategory,
}

impl From<HttpThreatV0_33> for HttpThreatFieldsV0_34 {
    fn from(input: HttpThreatV0_33) -> Self {
        Self {
            time: input.time,
            sensor: input.sensor,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            end_time: input.duration,
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
            cluster_id: Some(input.cluster_id),
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            category: input.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistTlsFieldsV0_36 {
    pub sensor: String,
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
    pub category: EventCategory,
}

impl From<BlocklistTlsFieldsV0_36> for BlocklistTlsFields {
    fn from(input: BlocklistTlsFieldsV0_36) -> Self {
        Self {
            sensor: input.sensor,
            src_addr: input.src_addr,
            src_port: input.src_port,
            dst_addr: input.dst_addr,
            dst_port: input.dst_port,
            proto: input.proto,
            end_time: input.last_time,
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
            confidence: 0.0,
            category: EventCategory::InitialAccess,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NetworkThreatV0_33 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
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
    pub category: EventCategory,
}

impl From<NetworkThreatV0_33> for NetworkThreat {
    fn from(input: NetworkThreatV0_33) -> Self {
        Self {
            time: input.time,
            sensor: input.sensor,
            orig_addr: input.orig_addr,
            orig_port: input.orig_port,
            resp_addr: input.resp_addr,
            resp_port: input.resp_port,
            proto: input.proto,
            service: input.service,
            end_time: input.last_time,
            content: input.content,
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: Some(input.cluster_id),
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            triage_scores: input.triage_scores,
            category: input.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct WindowsThreatV0_33 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
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
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl From<WindowsThreatV0_33> for WindowsThreat {
    fn from(input: WindowsThreatV0_33) -> Self {
        Self {
            time: input.time,
            sensor: input.sensor,
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
            cluster_id: Some(input.cluster_id),
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            triage_scores: input.triage_scores,
            category: input.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExtraThreatV0_33 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: usize,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: EventCategory,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl From<ExtraThreatV0_33> for ExtraThreat {
    fn from(input: ExtraThreatV0_33) -> Self {
        Self {
            time: input.time,
            sensor: input.sensor,
            service: input.service,
            content: input.content,
            db_name: input.db_name,
            rule_id: input.rule_id,
            matched_to: input.matched_to,
            cluster_id: Some(input.cluster_id),
            attack_kind: input.attack_kind,
            confidence: input.confidence,
            triage_scores: input.triage_scores,
            category: input.category,
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

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct AccountV0_34 {
    pub username: String,
    pub(crate) password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    pub language: Option<String>,
    pub theme: Option<String>,
    pub(crate) creation_time: DateTime<Utc>,
    pub(crate) last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u8>,
    pub(crate) password_hash_algorithm: PasswordHashAlgorithm,
    pub(crate) password_last_modified_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct AccountV0_36 {
    pub username: String,
    pub(crate) password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    pub language: Option<String>,
    pub theme: Option<String>,
    pub(crate) creation_time: DateTime<Utc>,
    pub(crate) last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u8>,
    pub(crate) password_hash_algorithm: PasswordHashAlgorithm,
    pub(crate) password_last_modified_at: DateTime<Utc>,
    pub customer_ids: Option<Vec<u32>>,
}

impl From<AccountV0_34> for AccountV0_36 {
    fn from(input: AccountV0_34) -> Self {
        Self {
            username: input.username,
            password: input.password,
            role: input.role,
            name: input.name,
            department: input.department,
            language: input.language,
            theme: None,
            creation_time: input.creation_time,
            last_signin_time: input.last_signin_time,
            allow_access_from: input.allow_access_from,
            max_parallel_sessions: input.max_parallel_sessions,
            password_hash_algorithm: input.password_hash_algorithm,
            password_last_modified_at: input.password_last_modified_at,
            customer_ids: match input.role {
                Role::SystemAdministrator => None,
                _ => Some(Vec::new()),
            },
        }
    }
}

impl From<AccountV0_36> for Account {
    fn from(input: AccountV0_36) -> Self {
        Self {
            username: input.username,
            password: input.password,
            role: input.role,
            name: input.name,
            department: input.department,
            language: input.language,
            theme: input.theme,
            creation_time: input.creation_time,
            last_signin_time: input.last_signin_time,
            allow_access_from: input.allow_access_from,
            max_parallel_sessions: input.max_parallel_sessions,
            password_hash_algorithm: input.password_hash_algorithm,
            password_last_modified_at: input.password_last_modified_at,
            customer_ids: input.customer_ids,
            failed_login_attempts: 0,
            locked_out_until: None,
            is_suspended: false,
        }
    }
}

impl From<Account> for AccountV0_34 {
    fn from(input: Account) -> Self {
        Self {
            username: input.username,
            password: input.password,
            role: input.role,
            name: input.name,
            department: input.department,
            language: input.language,
            theme: input.theme,
            creation_time: input.creation_time,
            last_signin_time: input.last_signin_time,
            allow_access_from: input.allow_access_from,
            max_parallel_sessions: input.max_parallel_sessions,
            password_hash_algorithm: input.password_hash_algorithm,
            password_last_modified_at: input.password_last_modified_at,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Giganto {
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct NodeV0_29 {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<NodeProfile>,
    pub profile_draft: Option<NodeProfile>,
    pub agents: Vec<Agent>,
    pub giganto: Option<Giganto>,
    pub creation_time: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct InnerV0_29 {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<NodeProfile>,
    pub profile_draft: Option<NodeProfile>,
    pub creation_time: DateTime<Utc>,
    pub agents: Vec<String>,
    pub giganto: Option<Giganto>,
}

impl From<NodeV0_29> for InnerV0_29 {
    fn from(input: NodeV0_29) -> Self {
        Self {
            id: input.id,
            name: input.name,
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            creation_time: input.creation_time,
            agents: input.agents.iter().map(|a| a.key.clone()).collect(),
            giganto: input.giganto,
        }
    }
}

impl From<InnerV0_29> for InnerNode {
    fn from(input: InnerV0_29) -> Self {
        Self {
            id: input.id,
            name: input.name,
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            external_services: input
                .giganto
                .map_or_else(Vec::new, |_| vec!["giganto".to_string()]),
            creation_time: input.creation_time,
        }
    }
}

impl Indexable for InnerV0_29 {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::from(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .serialize(self)
            .unwrap_or_default()
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TidbV0_39 {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: TidbKind,
    pub category: EventCategory,
    pub version: String,
    pub patterns: Vec<RuleV0_39>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RuleV0_39 {
    pub rule_id: u32,
    pub category: EventCategory,
    pub name: String,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
}

impl TryFrom<TidbV0_39> for Tidb {
    type Error = anyhow::Error;

    fn try_from(input: TidbV0_39) -> Result<Self, Self::Error> {
        Ok(Self {
            id: input.id,
            name: input.name,
            description: input.description,
            kind: input.kind,
            category: input.category,
            version: input.version,
            patterns: input
                .patterns
                .into_iter()
                .map(|rule| TidbRule {
                    rule_id: rule.rule_id,
                    category: rule.category,
                    name: rule.name,
                    kind: None, // Old rules do not have kind
                    description: rule.description,
                    references: rule.references,
                    samples: rule.samples,
                    signatures: rule.signatures,
                    confidence: None, // Old rules do not have confidence
                })
                .collect(),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FilterValueV0_39 {
    pub directions: Option<Vec<FlowKind>>,
    pub keywords: Option<Vec<String>>,
    pub network_tags: Option<Vec<String>>,
    pub customers: Option<Vec<String>>,
    pub endpoints: Option<Vec<FilterEndpoint>>,
    pub sensors: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
    pub devices: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
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

impl From<FilterValueV0_39> for crate::Filter {
    fn from(old_value: FilterValueV0_39) -> Self {
        use crate::PeriodForSearch;

        Self {
            username: String::new(), // Will be set from key
            name: String::new(),     // Will be set from key
            directions: old_value.directions,
            keywords: old_value.keywords,
            network_tags: old_value.network_tags,
            customers: old_value.customers,
            endpoints: old_value.endpoints,
            sensors: old_value.sensors,
            os: old_value.os,
            devices: old_value.devices,
            hostnames: old_value.hostnames,
            user_ids: old_value.user_ids,
            user_names: old_value.user_names,
            user_departments: old_value.user_departments,
            countries: old_value.countries,
            categories: old_value.categories,
            levels: old_value.levels,
            kinds: old_value.kinds,
            learning_methods: old_value.learning_methods,
            confidence: old_value.confidence,
            period: PeriodForSearch::Recent("1 hour".to_string()),
        }
    }
}
