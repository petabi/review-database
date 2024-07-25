//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

mod migration_structures;

use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{Agent, AgentStatus, Giganto, Indexed, IterableMap};

/// The range of versions that use the current database format.
///
/// The range should include all the earlier, released versions that use the current database
/// format, and exclude the first future version that uses a new database format.
///
/// # Examples
///
/// ```rust
/// // The current version is 0.4.1 and the database format hasn't been changed since 0.3.0.
/// // This should include future patch versions such as 0.4.2, 0.4.3, etc. since they won't
/// // change the database format.
/// const COMPATIBLE_VERSION: &str = ">=0.3,<0.5.0-alpha";
/// ```
///
/// ```rust
/// // The current version is 0.5.0-alpha.4 and the database format hasn't been changed since
/// // 0.5.0-alpha.2. This shouldn't include any future version since we cannot guarantee that
/// // the database format won't be changed in the future alpha or beta versions.
/// const COMPATIBLE_VERSION: &str = ">=0.5.0-alpha.2,<=0.5.0-alpha.4";
/// ```
const COMPATIBLE_VERSION_REQ: &str = ">=0.29.0,<0.30.0-alpha";

/// Migrates data exists in `PostgresQL` to Rocksdb if necessary.
///
/// Migration is supported for current released version only. And the migrated data
/// and related interface should be removed from `PostgresQL` database in the next released
/// version.
///
/// # Errors
///
/// Returns an error if the data hasn't been migrated successfully to Rocksdb.
pub async fn migrate_backend<P: AsRef<Path>>(
    _: &super::Database,
    _: &super::Store,
    _: P,
) -> Result<()> {
    // Below is an example for cases when data migration between `PostgreSQL`
    // and RocksDB is needed.
    // let path = data_dir.as_ref();
    // let file = path.join("VERSION");

    // let version = read_version_file(&file)?;

    // let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
    //     unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    // };
    // if compatible.matches(&version) {
    //     backend_0_23(db, store).await?;
    // }
    Ok(())
}

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(data_dir: P, backup_dir: P) -> Result<()> {
    type Migration = (VersionReq, Version, fn(&crate::Store) -> anyhow::Result<()>);

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };

    let (data, data_ver) = retrieve_or_create_version(data_dir)?;
    let (backup, backup_ver) = retrieve_or_create_version(backup_dir)?;

    if data_ver != backup_ver {
        return Err(anyhow!(
            "mismatched database version {data_ver} and backup version {backup_ver}"
        ));
    }

    let mut version = data_ver;
    if compatible.matches(&version) {
        return Ok(());
    }

    // A list of migrations where each item is a tuple of (version requirement, to version,
    // migration function).
    //
    // * The "version requirement" should include all the earlier, released versions that use the
    //   database format the migration function can handle, and exclude the first future version
    //   that uses a new database format.
    // * The "to version" should be the first future version that uses a new database format.
    // * The "migration function" should migrate the database from the version before "to version"
    //   to "to version". The function name should be in the form of "migrate_A_to_B" where A is
    //   the first version (major.minor) in the "version requirement" and B is the "to version"
    //   (major.minor). (NOTE: Once we release 1.0.0, A and B will contain the major version only.)
    let migration: Vec<Migration> = vec![
        (
            VersionReq::parse(">=0.25.0,<0.26.0")?,
            Version::parse("0.26.0")?,
            migrate_0_25_to_0_26,
        ),
        (
            VersionReq::parse(">=0.26.0,<0.28.0")?,
            Version::parse("0.28.0")?,
            migrate_0_26_to_0_28,
        ),
        (
            VersionReq::parse(">=0.28.0,<0.29.0-alpha.1")?,
            Version::parse("0.29.0-alpha.1")?,
            migrate_0_28_to_0_29_0,
        ),
    ];

    let mut store = super::Store::new(data_dir, backup_dir)?;
    store.backup(false, 1)?;

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(&store)?;
        version = to.clone();
        if compatible.matches(&version) {
            create_version_file(&backup).context("failed to update VERSION")?;
            return create_version_file(&data).context("failed to update VERSION");
        }
    }

    store.purge_old_backups(0)?;
    Err(anyhow!("migration from {version} is not supported",))
}

/// Recursively creates `path` if not existed, creates the VERSION file
/// under `path` if missing with current version number. Returns VERSION
/// file path with VERSION number written on file.
///
/// # Errors
///
/// Returns an error if VERSION cannot be retrieved or created.
fn retrieve_or_create_version<P: AsRef<Path>>(path: P) -> Result<(PathBuf, Version)> {
    let path = path.as_ref();
    let file = path.join("VERSION");

    if !path.exists() {
        create_dir_all(path)?;
    }
    if path
        .read_dir()
        .context("cannot read data dir")?
        .next()
        .is_none()
    {
        create_version_file(&file)?;
    }

    let version = read_version_file(&file)?;
    Ok((file, version))
}

/// Creates the VERSION file in the data directory.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be created or written.
fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
    Ok(())
}

/// Reads the VERSION file in the data directory and returns its contents.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be read or parsed.
fn read_version_file(path: &Path) -> Result<Version> {
    let mut ver = String::new();
    File::open(path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    Version::parse(&ver).context("cannot parse VERSION")
}

fn migrate_0_28_to_0_29_0(store: &super::Store) -> Result<()> {
    migrate_event_struct(store)?;
    migrate_0_29_node(store)?;
    migrate_0_29_account(store)
}

fn migrate_event_struct(store: &super::Store) -> Result<()> {
    use migration_structures::{
        BlockListConnBeforeV29, BlockListHttpBeforeV29, BlockListNtlmBeforeV29,
        BlockListSmtpBeforeV29, BlockListSshBeforeV29, BlockListTlsBeforeV29, DgaBeforeV29,
        HttpThreatBeforeV29, NonBrowserBeforeV29,
    };
    use num_traits::FromPrimitive;

    use crate::event::{
        BlockListConnFields, BlockListHttpFields, BlockListNtlmFields, BlockListSmtpFields,
        BlockListSshFields, BlockListTlsFields, DgaFields, EventKind, HttpThreatFields,
        NonBrowserFields,
    };

    let event_db = store.events();
    let iter = event_db.raw_iter_forward();
    for event in iter {
        let (k, v) = event.map_err(|e| anyhow!("Failed to read events database: {e:?}"))?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let kind = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(event_kind) = EventKind::from_i128(kind) else {
            return Err(anyhow!("Failed to migrate events: invalid event kind"));
        };

        match event_kind {
            EventKind::HttpThreat => {
                update_event_db_with_new_event::<HttpThreatBeforeV29, HttpThreatFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::DomainGenerationAlgorithm => {
                update_event_db_with_new_event::<DgaBeforeV29, DgaFields>(&k, &v, &event_db)?;
            }
            EventKind::NonBrowser => {
                update_event_db_with_new_event::<NonBrowserBeforeV29, NonBrowserFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListHttp => {
                update_event_db_with_new_event::<BlockListHttpBeforeV29, BlockListHttpFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListConn => {
                update_event_db_with_new_event::<BlockListConnBeforeV29, BlockListConnFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListNtlm => {
                update_event_db_with_new_event::<BlockListNtlmBeforeV29, BlockListNtlmFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListSmtp => {
                update_event_db_with_new_event::<BlockListSmtpBeforeV29, BlockListSmtpFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListSsh => {
                update_event_db_with_new_event::<BlockListSshBeforeV29, BlockListSshFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::BlockListTls => {
                update_event_db_with_new_event::<BlockListTlsBeforeV29, BlockListTlsFields>(
                    &k, &v, &event_db,
                )?;
            }
            _ => continue,
        }
    }
    Ok(())
}

fn migrate_0_29_node(store: &super::Store) -> Result<()> {
    use std::collections::HashMap;

    use bincode::Options;
    use chrono::{DateTime, Utc};

    use crate::IterableMap;
    use crate::{Node, NodeProfile};

    type PortNumber = u16;

    #[derive(Clone, Deserialize, Serialize)]
    pub struct OldNode {
        pub id: u32,
        pub name: String,
        pub name_draft: Option<String>,
        pub settings: Option<OldNodeSettings>,
        pub settings_draft: Option<OldNodeSettings>,
        pub creation_time: DateTime<Utc>,
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
    pub struct OldNodeSettings {
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,

        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,

        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,

        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,

        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,

        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,

        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,
    }

    impl From<OldNodeSettings> for NodeProfile {
        fn from(input: OldNodeSettings) -> Self {
            Self {
                customer_id: input.customer_id,
                description: input.description,
                hostname: input.hostname,
            }
        }
    }

    impl TryFrom<OldNode> for Node {
        type Error = anyhow::Error;

        fn try_from(input: OldNode) -> Result<Self, Self::Error> {
            use migration_structures::{
                DumpHttpContentType, DumpItem, GigantoConfig, HogConfig, PigletConfig,
                ProtocolForHog,
            };

            let mut giganto = None;
            let mut agents = vec![None, None, None];
            let status = crate::AgentStatus::Enabled;
            if let Some(s) = input.settings.as_ref() {
                if s.hog {
                    let config = HogConfig {
                        active_protocols: if s.protocols {
                            let mut list: Vec<_> = s.protocol_list.keys().cloned().collect();
                            list.sort_unstable();

                            let res_list = list
                                .into_iter()
                                .filter_map(|s| ProtocolForHog::from_str(&s).ok())
                                .collect();
                            Some(res_list)
                        } else {
                            Some(Vec::new())
                        },
                        active_sources: if s.sensors {
                            let mut list: Vec<_> = s.sensor_list.keys().cloned().collect();
                            list.sort_unstable();
                            Some(list)
                        } else {
                            Some(Vec::new())
                        },
                        giganto_publish_srv_addr: s.hog_giganto_ip.map(|ip| {
                            let port = s.hog_giganto_port.unwrap_or(u16::MIN);
                            SocketAddr::new(ip, port)
                        }),
                        cryptocurrency_mining_pool: String::new(),
                        log_dir: String::new(),
                        export_dir: String::new(),
                        services_path: String::new(),
                    };
                    let config = toml::to_string(&config)?.try_into()?;
                    let agent = Agent {
                        node: input.id,
                        key: "hog".to_string(),
                        kind: crate::AgentKind::Hog,
                        config: Some(config),
                        draft: None,
                        status,
                    };
                    agents[0] = Some(agent);
                }

                if s.piglet {
                    let config = PigletConfig {
                        dpdk_args: String::new(),
                        dpdk_input: Vec::new(),
                        dpdk_output: Vec::new(),
                        src_mac: String::new(),
                        dst_mac: String::new(),
                        log_dir: String::new(),
                        dump_dir: String::new(),
                        dump_items: {
                            let mut list = Vec::new();
                            if s.save_packets {
                                list.push(DumpItem::Pcap);
                            }
                            if s.http {
                                list.push(DumpItem::Http);
                            }
                            if s.smtp_eml {
                                list.push(DumpItem::Eml);
                            }
                            if s.ftp {
                                list.push(DumpItem::Ftp);
                            }

                            if list.is_empty() {
                                Some(Vec::new())
                            } else {
                                Some(list)
                            }
                        },
                        dump_http_content_types: {
                            let mut list = Vec::new();
                            if s.html || s.txt {
                                list.push(DumpHttpContentType::Txt);
                            }
                            if s.office {
                                list.push(DumpHttpContentType::Office);
                            }
                            if s.exe {
                                list.push(DumpHttpContentType::Exe);
                            }
                            if s.pdf {
                                list.push(DumpHttpContentType::Pdf);
                            }

                            if list.is_empty() {
                                Some(Vec::new())
                            } else {
                                Some(list)
                            }
                        },
                        giganto_ingest_srv_addr: s.piglet_giganto_ip.map_or(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN),
                            |ip| {
                                let port = s.piglet_giganto_port.unwrap_or(u16::MIN);
                                SocketAddr::new(ip, port)
                            },
                        ),
                        giganto_name: String::new(),
                        pcap_max_size: u32::MAX,
                    };
                    let config = toml::to_string(&config)?.try_into()?;
                    let agent = Agent {
                        node: input.id,
                        key: "piglet".to_string(),
                        kind: crate::AgentKind::Piglet,
                        config: Some(config),
                        draft: None,
                        status,
                    };
                    agents[1] = Some(agent);
                }

                if s.reconverge {
                    let config = String::new().try_into()?;
                    let agent = Agent {
                        node: input.id,
                        key: "reconverge".to_string(),
                        kind: crate::AgentKind::Reconverge,
                        config: Some(config),
                        draft: None,
                        status,
                    };
                    agents[2] = Some(agent);
                }

                if s.giganto {
                    giganto = Some(Giganto {
                        status: AgentStatus::Enabled,
                        draft: None,
                    });
                }
            }
            if let Some(s) = input.settings_draft.as_ref() {
                if s.hog {
                    let draft = HogConfig {
                        active_protocols: if s.protocols {
                            let mut list: Vec<_> = s.protocol_list.keys().cloned().collect();
                            list.sort_unstable();

                            let res_list = list
                                .into_iter()
                                .filter_map(|s| ProtocolForHog::from_str(&s).ok())
                                .collect();
                            Some(res_list)
                        } else {
                            Some(Vec::new())
                        },
                        active_sources: if s.sensors {
                            let mut list: Vec<_> = s.sensor_list.keys().cloned().collect();
                            list.sort_unstable();
                            Some(list)
                        } else {
                            Some(Vec::new())
                        },
                        giganto_publish_srv_addr: s.hog_giganto_ip.map(|ip| {
                            let port = s.hog_giganto_port.unwrap_or(u16::MIN);
                            SocketAddr::new(ip, port)
                        }),
                        cryptocurrency_mining_pool: String::new(),
                        log_dir: String::new(),
                        export_dir: String::new(),
                        services_path: String::new(),
                    };
                    let draft = toml::to_string(&draft)?.try_into()?;
                    if let Some(a) = &mut agents[0] {
                        a.draft = Some(draft);
                    } else {
                        agents[0] = Some(Agent {
                            node: input.id,
                            key: "hog".to_string(),
                            kind: crate::AgentKind::Hog,
                            config: None,
                            draft: Some(draft),
                            status,
                        });
                    }
                }

                if s.piglet {
                    let draft = PigletConfig {
                        dpdk_args: String::new(),
                        dpdk_input: Vec::new(),
                        dpdk_output: Vec::new(),
                        src_mac: String::new(),
                        dst_mac: String::new(),
                        log_dir: String::new(),
                        dump_dir: String::new(),
                        dump_items: {
                            let mut list = Vec::new();
                            if s.save_packets {
                                list.push(DumpItem::Pcap);
                            }
                            if s.http {
                                list.push(DumpItem::Http);
                            }
                            if s.smtp_eml {
                                list.push(DumpItem::Eml);
                            }
                            if s.ftp {
                                list.push(DumpItem::Ftp);
                            }

                            if list.is_empty() {
                                Some(Vec::new())
                            } else {
                                Some(list)
                            }
                        },
                        dump_http_content_types: {
                            let mut list = Vec::new();
                            if s.html || s.txt {
                                list.push(DumpHttpContentType::Txt);
                            }
                            if s.office {
                                list.push(DumpHttpContentType::Office);
                            }
                            if s.exe {
                                list.push(DumpHttpContentType::Exe);
                            }
                            if s.pdf {
                                list.push(DumpHttpContentType::Pdf);
                            }

                            if list.is_empty() {
                                Some(Vec::new())
                            } else {
                                Some(list)
                            }
                        },
                        giganto_ingest_srv_addr: s.piglet_giganto_ip.map_or(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN),
                            |ip| {
                                let port = s.piglet_giganto_port.unwrap_or(u16::MIN);
                                SocketAddr::new(ip, port)
                            },
                        ),
                        giganto_name: String::new(),
                        pcap_max_size: u32::MAX,
                    };
                    let draft = toml::to_string(&draft)?.try_into()?;
                    if let Some(a) = &mut agents[1] {
                        a.draft = Some(draft);
                    } else {
                        agents[1] = Some(Agent {
                            node: input.id,
                            key: "piglet".to_string(),
                            kind: crate::AgentKind::Piglet,
                            config: None,
                            draft: Some(draft),
                            status,
                        });
                    }
                }

                if s.reconverge {
                    let draft = String::new().try_into()?;
                    if let Some(a) = &mut agents[1] {
                        a.draft = Some(draft);
                    } else {
                        agents[2] = Some(Agent {
                            node: input.id,
                            key: "reconverge".to_string(),
                            kind: crate::AgentKind::Reconverge,
                            config: None,
                            draft: Some(draft),
                            status,
                        });
                    }
                }
                if s.giganto {
                    let draft = GigantoConfig {
                        ingest_srv_addr: s.giganto_ingestion_ip.map_or(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN),
                            |ip| {
                                let port = s.giganto_ingestion_port.unwrap_or(u16::MIN);
                                SocketAddr::new(ip, port)
                            },
                        ),
                        publish_srv_addr: s.giganto_publish_ip.map_or(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN),
                            |ip| {
                                let port = s.giganto_publish_port.unwrap_or(u16::MIN);
                                SocketAddr::new(ip, port)
                            },
                        ),
                        graphql_srv_addr: s.giganto_graphql_ip.map_or(
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN),
                            |ip| {
                                let port = s.giganto_graphql_port.unwrap_or(u16::MIN);
                                SocketAddr::new(ip, port)
                            },
                        ),
                        data_dir: String::new(),
                        log_dir: String::new(),
                        export_dir: String::new(),
                        retention: {
                            let days = u64::from(s.retention_period.unwrap_or(u16::MAX));
                            std::time::Duration::from_secs(days * 24 * 60 * 60)
                        },
                        max_open_files: i32::MAX,
                        max_mb_of_level_base: u64::MIN,
                        num_of_thread: i32::MAX,
                        max_sub_compactions: u32::MAX,
                        ack_transmission: u16::MAX,
                    };
                    let draft = Some(toml::to_string(&draft)?.try_into()?);
                    giganto = Some(Giganto {
                        status: AgentStatus::Enabled,
                        draft,
                    });
                }
            }
            Ok(Self {
                id: input.id,
                name: input.name,
                name_draft: input.name_draft,
                profile: input.settings.map(std::convert::Into::into),
                profile_draft: input.settings_draft.map(std::convert::Into::into),
                agents: agents.into_iter().flatten().collect(),
                giganto,
                creation_time: input.creation_time,
            })
        }
    }

    let map = store.node_map();
    let raw = map.raw();
    let mut nodes = vec![];
    for (_key, old_value) in raw.iter_forward()? {
        let old_node = bincode::DefaultOptions::new()
            .deserialize::<OldNode>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;
        match TryInto::<Node>::try_into(old_node) {
            Ok(new_node) => {
                raw.deactivate(new_node.id)?;
                nodes.push(new_node);
            }
            Err(e) => {
                warn!("Skip the migration for an item: {e}");
            }
        }
    }
    raw.clear_inactive()?;
    for node in nodes {
        let _ = map.put(node)?;
    }
    Ok(())
}

fn migrate_0_29_account(store: &super::Store) -> Result<()> {
    use bincode::Options;
    use chrono::{DateTime, Utc};

    use crate::account::{PasswordHashAlgorithm, Role, SaltedPassword};
    use crate::types::Account;

    #[derive(Deserialize, Serialize)]
    pub struct OldAccount {
        pub username: String,
        password: SaltedPassword,
        pub role: Role,
        pub name: String,
        pub department: String,
        creation_time: DateTime<Utc>,
        last_signin_time: Option<DateTime<Utc>>,
        pub allow_access_from: Option<Vec<IpAddr>>,
        pub max_parallel_sessions: Option<u32>,
        password_hash_algorithm: PasswordHashAlgorithm,
    }

    impl From<OldAccount> for Account {
        fn from(input: OldAccount) -> Self {
            Self {
                username: input.username,
                password: input.password,
                role: input.role,
                name: input.name,
                department: input.department,
                language: None,
                creation_time: input.creation_time,
                last_signin_time: input.last_signin_time,
                allow_access_from: input.allow_access_from,
                max_parallel_sessions: input.max_parallel_sessions,
                password_hash_algorithm: input.password_hash_algorithm,
                password_last_modified_at: Utc::now(),
            }
        }
    }

    let map = store.account_map();
    let raw = map.raw();
    let mut accounts = vec![];
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<OldAccount>(&old_value)?;
        raw.delete(&key)?;
        accounts.push(old.into());
    }
    for account in accounts {
        map.insert(&account)?;
    }
    Ok(())
}

fn update_event_db_with_new_event<'a, T, K>(
    k: &[u8],
    v: &'a [u8],
    event_db: &crate::EventDb,
) -> Result<()>
where
    T: Deserialize<'a> + Into<K>,
    K: Serialize,
{
    let Ok(from_event) = bincode::deserialize::<T>(v) else {
        return Err(anyhow!("Failed to migrate events: invalid event value"));
    };
    let to_event: K = from_event.into();
    let new = bincode::serialize(&to_event).unwrap_or_default();
    event_db.update((k, v), (k, &new))?;
    Ok(())
}

fn migrate_0_26_to_0_28(store: &super::Store) -> Result<()> {
    migrate_outlier_info(store)?;
    migrate_account_policy(store)
}

fn migrate_outlier_info(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::collections::IterableMap;
    use crate::OutlierInfoKey;

    let map = store.outlier_map();
    let raw = map.raw();
    for (key, value) in raw.iter_forward()? {
        let (model_id, timestamp, rank, id, source) = bincode::DefaultOptions::new()
            .deserialize::<(i32, i64, i64, i64, String)>(&key)
            .context("Failed to migrate node database: invalid node value")?;
        let new_key = OutlierInfoKey {
            model_id,
            timestamp,
            rank,
            id,
            source,
        };
        let new_key = new_key.to_bytes();
        raw.update((&key, &value), (&new_key, &value))?;
    }
    Ok(())
}

fn migrate_account_policy(store: &super::Store) -> Result<()> {
    use bincode::Options;

    #[derive(Deserialize, Serialize)]
    pub struct OldAccountPolicy {
        pub expiration_time: i64,
    }

    let key = b"account policy key";
    let map = store.account_policy_map();
    let raw = map.raw();

    for (cur_key, _value) in raw.iter_forward()? {
        if cur_key.as_ref() != key {
            raw.delete(&cur_key)?;
        }
    }

    if let Some(old) = raw.get(key)? {
        let old: OldAccountPolicy = bincode::DefaultOptions::new().deserialize(old.as_ref())?;
        let secs = u32::try_from(old.expiration_time)?;
        raw.delete(key)?;
        map.init_expiry_period(secs)?;
    }
    Ok(())
}

fn migrate_0_25_to_0_26(store: &super::Store) -> Result<()> {
    use std::{borrow::Cow, collections::HashMap};

    use bincode::Options;
    use chrono::{DateTime, Utc};

    use crate::collections::Indexed;
    use crate::Indexable;
    use crate::IterableMap;

    type PortNumber = u16;

    #[derive(Deserialize, Serialize)]
    pub struct OldNode {
        pub id: u32,
        pub creation_time: DateTime<Utc>,
        as_is: Option<OldNodeSettings>,
        to_be: Option<OldNodeSettings>,
    }

    #[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
    #[derive(Deserialize, Serialize)]
    struct OldNodeSettings {
        pub name: String,
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,

        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,

        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,

        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,

        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,

        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,

        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    pub struct Node26Version {
        pub id: u32,
        pub name: String,
        pub name_draft: Option<String>,
        pub settings: Option<Settings26Version>,
        pub settings_draft: Option<Settings26Version>,
        pub creation_time: DateTime<Utc>,
    }

    impl Indexable for Node26Version {
        fn key(&self) -> Cow<[u8]> {
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

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
    pub struct Settings26Version {
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,

        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,

        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,

        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,

        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,

        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,

        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,
    }

    impl From<OldNodeSettings> for Settings26Version {
        fn from(input: OldNodeSettings) -> Self {
            Self {
                customer_id: input.customer_id,
                description: input.description,
                hostname: input.hostname,
                review: input.review,
                review_port: input.review_port,
                review_web_port: input.review_web_port,
                piglet: input.piglet,
                piglet_giganto_ip: input.piglet_giganto_ip,
                piglet_giganto_port: input.piglet_giganto_port,
                piglet_review_ip: input.piglet_review_ip,
                piglet_review_port: input.piglet_review_port,
                save_packets: input.save_packets,
                http: input.http,
                office: input.office,
                exe: input.exe,
                pdf: input.pdf,
                html: input.html,
                txt: input.txt,
                smtp_eml: input.smtp_eml,
                ftp: input.ftp,
                giganto: input.giganto,
                giganto_ingestion_ip: input.giganto_ingestion_ip,
                giganto_ingestion_port: input.giganto_ingestion_port,
                giganto_publish_ip: input.giganto_publish_ip,
                giganto_publish_port: input.giganto_publish_port,
                giganto_graphql_ip: input.giganto_graphql_ip,
                giganto_graphql_port: input.giganto_graphql_port,
                retention_period: input.retention_period,
                reconverge: input.reconverge,
                reconverge_review_ip: input.reconverge_review_ip,
                reconverge_review_port: input.reconverge_review_port,
                reconverge_giganto_ip: input.reconverge_giganto_ip,
                reconverge_giganto_port: input.reconverge_giganto_port,
                hog: input.hog,
                hog_review_ip: input.hog_review_ip,
                hog_review_port: input.hog_review_port,
                hog_giganto_ip: input.hog_giganto_ip,
                hog_giganto_port: input.hog_giganto_port,
                protocols: input.protocols,
                protocol_list: input.protocol_list,
                sensors: input.sensors,
                sensor_list: input.sensor_list,
            }
        }
    }

    impl TryFrom<OldNode> for Node26Version {
        type Error = &'static str;

        fn try_from(input: OldNode) -> Result<Self, Self::Error> {
            let (name, name_draft) = match (&input.as_is, &input.to_be) {
                (None, None) => {
                    return Err("Both `as_is` and `to_be` are `None`");
                }
                (None, Some(to_be)) => (to_be.name.to_string(), None),
                (Some(as_is), None) => (as_is.name.to_string(), None),
                (Some(as_is), Some(to_be)) => {
                    (as_is.name.to_string(), Some(to_be.name.to_string()))
                }
            };

            Ok(Self {
                id: input.id,
                name,
                name_draft,
                settings: input.as_is.map(std::convert::Into::into),
                settings_draft: input.to_be.map(std::convert::Into::into),
                creation_time: input.creation_time,
            })
        }
    }

    let map = store.node_map();
    let raw = map.raw();
    for (_key, old_value) in raw.iter_forward()? {
        let old_node = bincode::DefaultOptions::new()
            .deserialize::<OldNode>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;

        match TryInto::<Node26Version>::try_into(old_node) {
            Ok(new_node) => {
                raw.overwrite(&new_node)?;
            }
            Err(e) => {
                warn!("Skip the migration for an item: {e}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use rocksdb::Direction;
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::Store;

    #[allow(dead_code)]
    struct TestSchema {
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
        #[allow(dead_code)]
        fn new() -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn new_with_dir(db_dir: tempfile::TempDir, backup_dir: tempfile::TempDir) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn close(self) -> (tempfile::TempDir, tempfile::TempDir) {
            (self.db_dir, self.backup_dir)
        }
    }

    #[test]
    fn version() {
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid semver");
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");

        // The current version must match the compatible version requirement.
        if current.pre.is_empty() {
            assert!(compatible.matches(&current));
        } else if current.major == 0 && current.patch != 0 || current.major >= 1 {
            // A pre-release for a backward-compatible version.
            let non_pre = Version::new(current.major, current.minor, current.patch);
            assert!(compatible.matches(&non_pre));
        } else {
            assert!(compatible.matches(&current));
        }

        // A future, backward-incompatible version must not match the compatible version.
        let breaking = {
            let mut breaking = current;
            if breaking.major == 0 {
                breaking.minor += 1;
            } else {
                breaking.major += 1;
            }
            breaking
        };
        assert!(!compatible.matches(&breaking));
    }

    #[test]
    fn migrate_0_25_to_0_26_node() {
        type PortNumber = u16;
        use std::{
            collections::HashMap,
            net::{IpAddr, Ipv4Addr},
        };

        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        use crate::{collections::Indexed, Indexable};

        #[derive(Deserialize, Serialize, Clone)]
        pub struct OldNode {
            pub id: u32,
            pub creation_time: DateTime<Utc>,
            pub as_is: Option<OldNodeSettings>,
            pub to_be: Option<OldNodeSettings>,
        }

        #[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
        #[derive(Deserialize, Serialize, Clone)]
        struct OldNodeSettings {
            pub name: String,
            pub customer_id: u32,
            pub description: String,
            pub hostname: String,

            pub review: bool,
            pub review_port: Option<PortNumber>,
            pub review_web_port: Option<PortNumber>,

            pub piglet: bool,
            pub piglet_giganto_ip: Option<IpAddr>,
            pub piglet_giganto_port: Option<PortNumber>,
            pub piglet_review_ip: Option<IpAddr>,
            pub piglet_review_port: Option<PortNumber>,
            pub save_packets: bool,
            pub http: bool,
            pub office: bool,
            pub exe: bool,
            pub pdf: bool,
            pub html: bool,
            pub txt: bool,
            pub smtp_eml: bool,
            pub ftp: bool,

            pub giganto: bool,
            pub giganto_ingestion_ip: Option<IpAddr>,
            pub giganto_ingestion_port: Option<PortNumber>,
            pub giganto_publish_ip: Option<IpAddr>,
            pub giganto_publish_port: Option<PortNumber>,
            pub giganto_graphql_ip: Option<IpAddr>,
            pub giganto_graphql_port: Option<PortNumber>,
            pub retention_period: Option<u16>,

            pub reconverge: bool,
            pub reconverge_review_ip: Option<IpAddr>,
            pub reconverge_review_port: Option<PortNumber>,
            pub reconverge_giganto_ip: Option<IpAddr>,
            pub reconverge_giganto_port: Option<PortNumber>,

            pub hog: bool,
            pub hog_review_ip: Option<IpAddr>,
            pub hog_review_port: Option<PortNumber>,
            pub hog_giganto_ip: Option<IpAddr>,
            pub hog_giganto_port: Option<PortNumber>,
            pub protocols: bool,
            pub protocol_list: HashMap<String, bool>,

            pub sensors: bool,
            pub sensor_list: HashMap<String, bool>,
        }

        impl Indexable for OldNode {
            fn key(&self) -> Cow<[u8]> {
                if let Some(as_is) = &self.as_is {
                    Cow::from(as_is.name.as_bytes())
                } else if let Some(to_be) = &self.to_be {
                    Cow::from(to_be.name.as_bytes())
                } else {
                    panic!("Both `as_is` and `to_be` are `None`");
                }
            }

            fn value(&self) -> Vec<u8> {
                bincode::DefaultOptions::new()
                    .serialize(self)
                    .expect("serializable")
            }

            fn set_index(&mut self, index: u32) {
                self.id = index;
            }

            fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
                key
            }

            fn index(&self) -> u32 {
                self.id
            }
        }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Node26Version {
            pub id: u32,
            pub name: String,
            pub name_draft: Option<String>,
            pub settings: Option<Settings26Version>,
            pub settings_draft: Option<Settings26Version>,
            pub creation_time: DateTime<Utc>,
        }

        impl Indexable for Node26Version {
            fn key(&self) -> Cow<[u8]> {
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

        #[allow(clippy::struct_excessive_bools)]
        #[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
        pub struct Settings26Version {
            pub customer_id: u32,
            pub description: String,
            pub hostname: String,

            pub review: bool,
            pub review_port: Option<PortNumber>,
            pub review_web_port: Option<PortNumber>,

            pub piglet: bool,
            pub piglet_giganto_ip: Option<IpAddr>,
            pub piglet_giganto_port: Option<PortNumber>,
            pub piglet_review_ip: Option<IpAddr>,
            pub piglet_review_port: Option<PortNumber>,
            pub save_packets: bool,
            pub http: bool,
            pub office: bool,
            pub exe: bool,
            pub pdf: bool,
            pub html: bool,
            pub txt: bool,
            pub smtp_eml: bool,
            pub ftp: bool,

            pub giganto: bool,
            pub giganto_ingestion_ip: Option<IpAddr>,
            pub giganto_ingestion_port: Option<PortNumber>,
            pub giganto_publish_ip: Option<IpAddr>,
            pub giganto_publish_port: Option<PortNumber>,
            pub giganto_graphql_ip: Option<IpAddr>,
            pub giganto_graphql_port: Option<PortNumber>,
            pub retention_period: Option<u16>,

            pub reconverge: bool,
            pub reconverge_review_ip: Option<IpAddr>,
            pub reconverge_review_port: Option<PortNumber>,
            pub reconverge_giganto_ip: Option<IpAddr>,
            pub reconverge_giganto_port: Option<PortNumber>,

            pub hog: bool,
            pub hog_review_ip: Option<IpAddr>,
            pub hog_review_port: Option<PortNumber>,
            pub hog_giganto_ip: Option<IpAddr>,
            pub hog_giganto_port: Option<PortNumber>,
            pub protocols: bool,
            pub protocol_list: HashMap<String, bool>,

            pub sensors: bool,
            pub sensor_list: HashMap<String, bool>,
        }

        let settings = TestSchema::new();
        let map = settings.store.node_map();
        let node_db = map.raw();

        let old_node = OldNode {
            id: 0,
            creation_time: Utc::now(),
            as_is: None,
            to_be: Some(OldNodeSettings {
                name: "name".to_string(),
                customer_id: 20,
                description: "description".to_string(),
                hostname: "host".to_string(),
                review: true,
                review_port: Some(4040),
                review_web_port: Some(8442),
                piglet: true,
                piglet_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))),
                piglet_giganto_port: Some(3030),
                piglet_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                piglet_review_port: Some(4040),
                save_packets: true,
                http: false,
                office: false,
                exe: false,
                pdf: false,
                html: false,
                txt: false,
                smtp_eml: false,
                ftp: false,
                giganto: true,
                giganto_ingestion_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_ingestion_port: Some(3030),
                giganto_publish_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_publish_port: Some(3050),
                giganto_graphql_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_graphql_port: Some(5050),
                retention_period: Some(100),
                reconverge: false,
                reconverge_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                reconverge_review_port: Some(4040),
                reconverge_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                reconverge_giganto_port: Some(3050),
                hog: true,
                hog_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                hog_review_port: Some(4040),
                hog_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                hog_giganto_port: Some(3050),
                protocols: false,
                protocol_list: HashMap::new(),
                sensors: false,
                sensor_list: HashMap::new(),
            }),
        };

        assert!(node_db.insert(old_node.clone()).is_ok());
        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_25_to_0_26(&settings.store).is_ok());

        let map = settings.store.node_map();
        let node_db = map.raw();
        let new_node = node_db.get_by_key("name".as_bytes()).unwrap().unwrap();
        let new_node: Node26Version = bincode::DefaultOptions::new()
            .deserialize(new_node.as_ref())
            .expect("deserializable");

        assert_eq!(new_node.id, 0);
        assert_eq!(new_node.name, "name");
    }

    #[test]
    fn migrate_0_26_to_0_28_outlier_info() {
        use bincode::Options;

        use crate::tables::Iterable;

        let settings = TestSchema::new();
        let map = settings.store.outlier_map();
        let outlier_db = map.raw();

        let model_id = 123;
        let timestamp = 456;
        let rank = 789;
        let id = 0;
        let source = "some source".to_string();
        let distance = 3.1415926;
        let is_saved = true;
        let sample = crate::OutlierInfo {
            model_id,
            timestamp,
            rank,
            id,
            source,
            distance,
            is_saved,
        };

        let key = bincode::DefaultOptions::new()
            .serialize(&(model_id, timestamp, rank, id, &sample.source))
            .unwrap();
        let value = bincode::DefaultOptions::new()
            .serialize(&(distance, is_saved))
            .unwrap();
        assert!(outlier_db.insert(&key, &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_outlier_info(&settings.store).is_ok());

        let map = settings.store.outlier_map();
        assert_eq!(map.iter(Direction::Forward, None).count(), 1);
        let entries = map
            .get(model_id, Some(timestamp), Direction::Reverse, None)
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], sample);
    }

    #[test]
    fn migrate_0_26_to_0_28_account_policy() {
        use bincode::Options;
        use serde::Serialize;

        use crate::collections::IterableMap;

        #[derive(Serialize)]
        pub struct OldAccountPolicy {
            pub expiration_time: i64,
        }

        let key = b"account policy key";
        let settings = TestSchema::new();
        let map = settings.store.account_policy_map();
        let ap_db = map.raw();

        let time: u32 = 32;

        let value = bincode::DefaultOptions::new()
            .serialize(&OldAccountPolicy {
                expiration_time: i64::try_from(time).unwrap(),
            })
            .unwrap();
        assert!(ap_db.insert(key, &value).is_ok());
        assert!(ap_db.insert(b"error key", &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_account_policy(&settings.store).is_ok());

        let map = settings.store.account_policy_map();
        assert_eq!(map.raw().iter_forward().unwrap().count(), 1);
        let res = map.current_expiry_period();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Some(time));
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_conn() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListConnBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListConnBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            duration: 1230000,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListConn,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_http_threat() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::HttpThreatBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = HttpThreatBeforeV29 {
            time,
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            duration: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referer: "cluml.com".to_string(),
            version: "version".to_string(),
            user_agent: "review-database".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "status_msg".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 10,
            matched_to: "matched_to".to_string(),
            cluster_id: 200,
            attack_kind: "attack_kind".to_string(),
            confidence: 0.3,
        };

        let message = EventMessage {
            time,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_dga() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{migration::migration_structures::DgaBeforeV29, EventKind, EventMessage};

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = DgaBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            duration: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referer: "cluml.com".to_string(),
            version: "version".to_string(),
            user_agent: "review-database".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "status_msg".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            confidence: 0.3,
        };

        let message = EventMessage {
            time,
            kind: EventKind::DomainGenerationAlgorithm,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_non_browser() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::NonBrowserBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = NonBrowserBeforeV29 {
            source: "source_1".to_string(),
            session_end_time: time,
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referrer: "cluml.com".to_string(),
            version: "version".to_string(),
            user_agent: "review-database".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "status_msg".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_http() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListHttpBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListHttpBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            last_time: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referrer: "cluml.com".to_string(),
            version: "version".to_string(),
            user_agent: "review-database".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "status_msg".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListHttp,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_ntlm() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListNtlmBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListNtlmBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            last_time: 1,
            username: "cluml".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            server_nb_computer_name: "NB".to_string(),
            server_dns_computer_name: "dns".to_string(),
            server_tree_name: "tree".to_string(),
            success: "tf".to_string(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListNtlm,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_smtp() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListSmtpBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListSmtpBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            last_time: 1,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListSmtp,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_ssh() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListSshBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListSshBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            last_time: 1,
            version: 1,
            auth_success: "auth_success".to_string(),
            auth_attempts: 3,
            direction: "direction".to_string(),
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            host_key: "host_key".to_string(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListSsh,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_28_to_0_29_0_block_list_tls() {
        use std::net::IpAddr;

        use chrono::Utc;

        use crate::{
            migration::migration_structures::BlockListTlsBeforeV29, EventKind, EventMessage,
        };

        let settings = TestSchema::new();
        let time = Utc::now();
        let value = BlockListTlsBeforeV29 {
            source: "source_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            cipher: 10,
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "sub_country".to_string(),
            subject_org_name: "sub_org".to_string(),
            subject_common_name: "sub_comm".to_string(),
            validity_not_before: 11,
            validity_not_after: 12,
            subject_alt_name: "sub_alt".to_string(),
            issuer_country: "issuer_country".to_string(),
            issuer_org_name: "issuer_org".to_string(),
            issuer_org_unit_name: "issuer_org_unit".to_string(),
            issuer_common_name: "issuer_comm".to_string(),
            last_alert: 13,
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListTls,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_28_to_0_29_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_26_to_0_29_node() {
        type PortNumber = u16;
        use std::{
            collections::HashMap,
            net::{IpAddr, Ipv4Addr},
        };

        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        use crate::{
            collections::Indexed, migration::migration_structures::PigletConfig, Indexable,
        };

        #[derive(Clone, Deserialize, Serialize)]
        pub struct OldNode {
            pub id: u32,
            pub name: String,
            pub name_draft: Option<String>,
            pub settings: Option<OldNodeSettings>,
            pub settings_draft: Option<OldNodeSettings>,
            pub creation_time: DateTime<Utc>,
        }

        #[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
        #[derive(Deserialize, Serialize, Clone)]
        pub struct OldNodeSettings {
            pub customer_id: u32,
            pub description: String,
            pub hostname: String,

            pub review: bool,
            pub review_port: Option<PortNumber>,
            pub review_web_port: Option<PortNumber>,

            pub piglet: bool,
            pub piglet_giganto_ip: Option<IpAddr>,
            pub piglet_giganto_port: Option<PortNumber>,
            pub piglet_review_ip: Option<IpAddr>,
            pub piglet_review_port: Option<PortNumber>,
            pub save_packets: bool,
            pub http: bool,
            pub office: bool,
            pub exe: bool,
            pub pdf: bool,
            pub html: bool,
            pub txt: bool,
            pub smtp_eml: bool,
            pub ftp: bool,

            pub giganto: bool,
            pub giganto_ingestion_ip: Option<IpAddr>,
            pub giganto_ingestion_port: Option<PortNumber>,
            pub giganto_publish_ip: Option<IpAddr>,
            pub giganto_publish_port: Option<PortNumber>,
            pub giganto_graphql_ip: Option<IpAddr>,
            pub giganto_graphql_port: Option<PortNumber>,
            pub retention_period: Option<u16>,

            pub reconverge: bool,
            pub reconverge_review_ip: Option<IpAddr>,
            pub reconverge_review_port: Option<PortNumber>,
            pub reconverge_giganto_ip: Option<IpAddr>,
            pub reconverge_giganto_port: Option<PortNumber>,

            pub hog: bool,
            pub hog_review_ip: Option<IpAddr>,
            pub hog_review_port: Option<PortNumber>,
            pub hog_giganto_ip: Option<IpAddr>,
            pub hog_giganto_port: Option<PortNumber>,
            pub protocols: bool,
            pub protocol_list: HashMap<String, bool>,

            pub sensors: bool,
            pub sensor_list: HashMap<String, bool>,
        }

        impl Indexable for OldNode {
            fn key(&self) -> Cow<[u8]> {
                Cow::from(self.name.as_bytes())
            }

            fn value(&self) -> Vec<u8> {
                bincode::DefaultOptions::new()
                    .serialize(self)
                    .expect("serializable")
            }

            fn set_index(&mut self, index: u32) {
                self.id = index;
            }

            fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
                key
            }

            fn index(&self) -> u32 {
                self.id
            }
        }

        let settings = TestSchema::new();
        let map = settings.store.node_map();
        let node_db = map.raw();

        let old_node = OldNode {
            id: 0,
            name: "name".to_string(),
            name_draft: None,
            creation_time: Utc::now(),
            settings: None,
            settings_draft: Some(OldNodeSettings {
                customer_id: 20,
                description: "description".to_string(),
                hostname: "host".to_string(),
                review: true,
                review_port: Some(4040),
                review_web_port: Some(8442),
                piglet: true,
                piglet_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))),
                piglet_giganto_port: Some(3030),
                piglet_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                piglet_review_port: Some(4040),
                save_packets: true,
                http: false,
                office: false,
                exe: false,
                pdf: false,
                html: false,
                txt: false,
                smtp_eml: false,
                ftp: false,
                giganto: true,
                giganto_ingestion_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_ingestion_port: Some(3030),
                giganto_publish_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_publish_port: Some(3050),
                giganto_graphql_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                giganto_graphql_port: Some(5050),
                retention_period: Some(100),
                reconverge: false,
                reconverge_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                reconverge_review_port: Some(4040),
                reconverge_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                reconverge_giganto_port: Some(3050),
                hog: true,
                hog_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                hog_review_port: Some(4040),
                hog_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                hog_giganto_port: Some(3050),
                protocols: false,
                protocol_list: HashMap::new(),
                sensors: false,
                sensor_list: HashMap::new(),
            }),
        };

        let res = node_db.insert(old_node.clone());
        assert!(res.is_ok());
        let id = res.unwrap();
        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_29_node(&settings.store).is_ok());

        let map = settings.store.node_map();
        let (new_node, invalid_agent) = map.get_by_id(id).unwrap().unwrap();

        assert!(invalid_agent.is_empty());
        assert_eq!(new_node.id, id);
        assert_eq!(new_node.name, "name");
        assert_eq!(new_node.agents.len(), 2);
        assert_eq!(new_node.agents[0].key, "hog");
        assert!(new_node.agents[0].config.is_none());
        assert!(new_node.agents[0].draft.is_some());
        assert_eq!(new_node.agents[1].key, "piglet");
        assert!(new_node.agents[1].config.is_none());
        let draft = new_node.agents[1].draft.clone().unwrap();
        let piglet: PigletConfig = toml::from_str(draft.as_ref()).unwrap();
        assert!(piglet.dump_items.is_some());
        assert!(piglet.dump_http_content_types.is_some_and(|v| v.is_empty()));
    }

    #[test]
    fn migrate_0_26_to_0_29_account() {
        use std::net::IpAddr;

        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        use crate::account::{PasswordHashAlgorithm, Role, SaltedPassword};
        use crate::types::Account;

        #[derive(Deserialize, Serialize)]
        pub struct OldAccount {
            pub username: String,
            password: SaltedPassword,
            pub role: Role,
            pub name: String,
            pub department: String,
            creation_time: DateTime<Utc>,
            last_signin_time: Option<DateTime<Utc>>,
            pub allow_access_from: Option<Vec<IpAddr>>,
            pub max_parallel_sessions: Option<u32>,
            password_hash_algorithm: PasswordHashAlgorithm,
        }

        impl From<OldAccount> for Account {
            fn from(input: OldAccount) -> Self {
                Self {
                    username: input.username,
                    password: input.password,
                    role: input.role,
                    name: input.name,
                    department: input.department,
                    language: None,
                    creation_time: input.creation_time,
                    last_signin_time: input.last_signin_time,
                    allow_access_from: input.allow_access_from,
                    max_parallel_sessions: input.max_parallel_sessions,
                    password_hash_algorithm: input.password_hash_algorithm,
                    password_last_modified_at: Utc::now(),
                }
            }
        }

        impl From<Account> for OldAccount {
            fn from(input: Account) -> Self {
                Self {
                    username: input.username,
                    password: input.password,
                    role: input.role,
                    name: input.name,
                    department: input.department,
                    creation_time: input.creation_time,
                    last_signin_time: input.last_signin_time,
                    allow_access_from: input.allow_access_from,
                    max_parallel_sessions: input.max_parallel_sessions,
                    password_hash_algorithm: input.password_hash_algorithm,
                }
            }
        }

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        let mut test = Account::new(
            "test",
            "password",
            Role::SecurityAdministrator,
            "name".to_string(),
            "department".to_string(),
            None,
            None,
            None,
        )
        .unwrap();
        let old: OldAccount = test.clone().into();
        let value = bincode::DefaultOptions::new()
            .serialize(&old)
            .expect("serializable");

        assert!(raw.insert(old.username.as_bytes(), &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_29_account(&settings.store).is_ok());

        let map = settings.store.account_map();
        let res = map.get(&test.username);
        assert!(res.is_ok());
        let account = res.unwrap();
        if let Some(a) = &account {
            test.password_last_modified_at = a.password_last_modified_at;
        }
        assert_eq!(account, Some(test));
    }
}
