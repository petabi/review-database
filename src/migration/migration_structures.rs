use std::{net::SocketAddr, time::Duration};

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::{ExternalServiceConfig, ExternalServiceStatus};

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DumpItem {
    Pcap,
    Eml,
    Ftp,
    Http,
}

#[allow(dead_code)]
#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DumpHttpContentType {
    Office,
    Exe,
    Pdf,
    Vbs,
    Txt,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Deserialize, Serialize, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolForHog {
    Conn,
    Dns,
    Rdp,
    Http,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Giganto {
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
}
