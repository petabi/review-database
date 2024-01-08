//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};
use tracing::info;

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
const COMPATIBLE_VERSION_REQ: &str = ">=0.16.0,<0.22.0-alpha";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version. Or if `COMPATIBLE_VERSION_REQ` cannot be properly parsed.
pub fn migrate_data_dir<P: AsRef<Path>>(data_dir: P, backup_dir: P) -> Result<()> {
    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ)?;

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
    let migration: Vec<(_, _, fn(_) -> Result<_, _>)> = vec![
        (
            VersionReq::parse(">=0.12.0,<0.16.0")?,
            Version::parse("0.16.0")?,
            migrate_0_12_to_0_16,
        ),
        (
            VersionReq::parse(">=0.16.0,<0.20.0")?,
            Version::parse("0.20.0")?,
            migrate_0_16_to_0_20,
        ),
        (
            VersionReq::parse(">=0.20.0,<0.22.0")?,
            Version::parse("0.22.0")?,
            migrate_0_20_to_0_22,
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

// Update FtpBruteForce, LdapBruteForce, RdpBruteForce fields.
fn migrate_0_12_to_0_16(store: &super::Store) -> Result<()> {
    use crate::{
        event::{FtpBruteForceFields, LdapBruteForceFields, RdpBruteForceFields},
        EventKind,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use num_traits::FromPrimitive;

    #[derive(Deserialize, Serialize)]
    struct OldRdpBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub src_port: u16,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
    }

    impl From<(OldRdpBruteForceFields, DateTime<Utc>)> for RdpBruteForceFields {
        fn from(input: (OldRdpBruteForceFields, DateTime<Utc>)) -> Self {
            let (input, time) = input;
            Self {
                src_addr: input.src_addr,
                dst_addrs: vec![input.dst_addr],
                start_time: time,
                last_time: time,
                proto: input.proto,
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct OldFtpBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub user_list: Vec<String>,
        pub start_time: DateTime<Utc>,
        pub last_time: DateTime<Utc>,
        pub is_internal: bool,
    }

    impl From<OldFtpBruteForceFields> for FtpBruteForceFields {
        fn from(input: OldFtpBruteForceFields) -> Self {
            Self {
                src_addr: input.src_addr,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                user_list: input.user_list,
                start_time: input.start_time,
                last_time: input.last_time,
                is_internal: input.is_internal,
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct OldLdapBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub user_pw_list: Vec<(String, String)>,
        pub start_time: DateTime<Utc>,
        pub last_time: DateTime<Utc>,
    }

    impl From<OldLdapBruteForceFields> for LdapBruteForceFields {
        fn from(input: OldLdapBruteForceFields) -> Self {
            Self {
                src_addr: input.src_addr,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                user_pw_list: input.user_pw_list,
                start_time: input.start_time,
                last_time: input.last_time,
            }
        }
    }

    let event_db = store.events();
    for item in event_db.raw_iter_forward() {
        let (k, v) = item.context("Failed to read events Database")?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let key_timestamp = (key >> 64) as i64;
        let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        match kind {
            EventKind::FtpBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldFtpBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let ftp_event: FtpBruteForceFields = fields.into();
                let new = bincode::serialize(&ftp_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::LdapBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldLdapBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let ldap_event: LdapBruteForceFields = fields.into();
                let new = bincode::serialize(&ldap_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::RdpBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldRdpBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let dt = Utc.timestamp_nanos(key_timestamp);
                let rdp_event: RdpBruteForceFields = (fields, dt).into();
                let new = bincode::serialize(&rdp_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            _ => continue,
        }
    }
    Ok(())
}

// Update BlockListKerberos fields.
fn migrate_0_16_to_0_20(store: &super::Store) -> Result<()> {
    use crate::{event::BlockListKerberosFields, EventKind};
    use chrono::Utc;
    use num_traits::FromPrimitive;

    #[derive(Deserialize, Serialize)]
    struct OldBlockListKerberosFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub src_port: u16,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub last_time: i64,
        pub request_type: String,
        pub client: String,
        pub service: String,
        pub success: String,
        pub error_msg: String,
        pub from: i64,
        pub till: i64,
        pub cipher: String,
        pub forwardable: String,
        pub renewable: String,
        pub client_cert_subject: String,
        pub server_cert_subject: String,
    }

    impl From<OldBlockListKerberosFields> for BlockListKerberosFields {
        fn from(input: OldBlockListKerberosFields) -> Self {
            Self {
                source: input.source,
                src_addr: input.src_addr,
                src_port: input.src_port,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                last_time: input.last_time,
                client_time: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                server_time: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                error_code: 0,
                client_realm: String::new(),
                cname_type: 0,
                client_name: Vec::new(),
                realm: String::new(),
                sname_type: 0,
                service_name: Vec::new(),
            }
        }
    }

    let event_db = store.events();
    for item in event_db.raw_iter_forward() {
        let (k, v) = item.context("Failed to read events Database")?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        match kind {
            EventKind::BlockListKerberos => {
                let Ok(fields) = bincode::deserialize::<OldBlockListKerberosFields>(v.as_ref())
                else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let block_list_kerberos_event: BlockListKerberosFields = fields.into();
                let new = bincode::serialize(&block_list_kerberos_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            _ => continue,
        }
    }
    Ok(())
}

fn migrate_0_20_to_0_22(store: &super::Store) -> Result<()> {
    use crate::collections::Indexed;
    use crate::node::Node;
    use crate::{Indexable, IterableMap};
    use bincode::Options;
    use chrono::{DateTime, Utc};
    use ipnet::Ipv4Net;
    use std::collections::HashMap;

    type PortNumber = u16;

    #[derive(Deserialize, Serialize)]
    struct Nic {
        name: String,
        interface: Ipv4Net,
        gateway: IpAddr,
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Deserialize, Serialize)]
    struct OldNode {
        id: u32,
        name: String,
        customer_id: u32,
        description: String,
        hostname: String,
        nics: Vec<Nic>,                         // abandoned in new Node
        disk_usage_limit: Option<f32>,          // abandoned in new Node
        allow_access_from: Option<Vec<IpAddr>>, // abandoned in new Node
        review_id: Option<u32>,                 // abandoned in new Node
        ssh_port: PortNumber,                   // abandoned in new Node
        dns_server_ip: Option<IpAddr>,          // abandoned in new Node
        dns_server_port: Option<PortNumber>,    // abandoned in new Node
        syslog_server_ip: Option<IpAddr>,       // abandoned in new Node
        syslog_server_port: Option<PortNumber>, // abandoned in new Node
        review: bool,
        review_nics: Option<Vec<String>>,
        review_port: Option<PortNumber>,
        review_web_port: Option<PortNumber>,
        ntp_server_ip: Option<IpAddr>,       // abandoned in new Node
        ntp_server_port: Option<PortNumber>, // abandoned in new Node
        piglet: bool,
        giganto: bool,
        giganto_ingestion_nics: Option<Vec<String>>, // replaced with `giganto_ingestion_ip`
        giganto_ingestion_port: Option<PortNumber>,
        giganto_publish_nics: Option<Vec<String>>, // replaced with `giganto_publish_ip`
        giganto_publish_port: Option<PortNumber>,
        giganto_graphql_nics: Option<Vec<String>>, // replaced with `giganto_graphql_ip`
        giganto_graphql_port: Option<PortNumber>,
        reconverge: bool,
        hog: bool,
        creation_time: DateTime<Utc>,
    }

    impl Indexable for OldNode {
        fn key(&self) -> &[u8] {
            self.name.as_bytes()
        }

        fn value(&self) -> Vec<u8> {
            bincode::DefaultOptions::new()
                .serialize(self)
                .expect("serializable")
        }

        fn set_index(&mut self, index: u32) {
            self.id = index;
        }
    }

    fn extract_ip_from_nics(all_nics: &[Nic], target_nics: Option<Vec<String>>) -> Option<IpAddr> {
        target_nics.and_then(|target_nics| {
            all_nics
                .iter()
                .find(|nic| target_nics.contains(&nic.name))
                .map(|nic| std::net::IpAddr::V4(nic.interface.addr()))
        })
    }

    impl From<OldNode> for Node {
        fn from(input: OldNode) -> Self {
            let extracted_giganto_ingestion_ip =
                extract_ip_from_nics(input.nics.as_slice(), input.giganto_ingestion_nics);
            let extracted_giganto_publish_ip =
                extract_ip_from_nics(input.nics.as_slice(), input.giganto_publish_nics);
            let extracted_giganto_graphql_ip =
                extract_ip_from_nics(input.nics.as_slice(), input.giganto_graphql_nics);

            Self {
                id: input.id,
                name: input.name,
                customer_id: input.customer_id,
                description: input.description,
                hostname: input.hostname,
                review: input.review,
                review_port: input.review_port,
                review_web_port: input.review_web_port,
                piglet: input.piglet,
                piglet_giganto_ip: None,
                piglet_giganto_port: None,
                piglet_review_ip: None,
                piglet_review_port: None,
                save_packets: false,
                http: false,
                office: false,
                exe: false,
                pdf: false,
                html: false,
                txt: false,
                smtp_eml: false,
                ftp: false,
                giganto: input.giganto,
                giganto_ingestion_ip: extracted_giganto_ingestion_ip,
                giganto_ingestion_port: input.giganto_ingestion_port,
                giganto_publish_ip: extracted_giganto_publish_ip,
                giganto_publish_port: input.giganto_publish_port,
                giganto_graphql_ip: extracted_giganto_graphql_ip,
                giganto_graphql_port: input.giganto_graphql_port,
                retention_period: None,
                reconverge: input.reconverge,
                reconverge_review_ip: None,
                reconverge_review_port: None,
                reconverge_giganto_ip: None,
                reconverge_giganto_port: None,
                hog: input.hog,
                hog_review_ip: None,
                hog_review_port: None,
                hog_giganto_ip: None,
                hog_giganto_port: None,
                protocols: false,
                protocol_list: HashMap::new(),
                sensors: false,
                sensor_list: HashMap::new(),
                creation_time: input.creation_time,
            }
        }
    }

    let node_db = store.node_map();
    for (_key, old_value) in node_db.iter_forward()? {
        let old_node = bincode::DefaultOptions::new()
            .deserialize::<OldNode>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;
        let new_node: Node = old_node.into();
        node_db.overwrite(&new_node)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::COMPATIBLE_VERSION_REQ;
    use crate::{node::Node, Store};
    use semver::{Version, VersionReq};

    struct TestSchema {
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
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

        fn new_with_dir(db_dir: tempfile::TempDir, backup_dir: tempfile::TempDir) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

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
    fn migrate_0_12_to_0_16() {
        use crate::{EventKind, EventMessage};
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};
        use std::net::IpAddr;

        let settings = TestSchema::new();
        #[derive(Deserialize, Serialize)]
        struct OldRdpBruteForceFields {
            source: String,
            src_addr: IpAddr,
            src_port: u16,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
        }

        let time = Utc::now();
        let value = OldRdpBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            src_port: 40000,
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
        };

        let message = EventMessage {
            time,
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        #[derive(Deserialize, Serialize)]
        struct OldFtpBruteForceFields {
            source: String,
            src_addr: IpAddr,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
            user_list: Vec<String>,
            start_time: DateTime<Utc>,
            last_time: DateTime<Utc>,
            is_internal: bool,
        }

        let value = OldFtpBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            user_list: vec!["user_name".to_string()],
            start_time: time,
            last_time: time,
            is_internal: false,
        };

        let message = EventMessage {
            time,
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        #[derive(Deserialize, Serialize)]
        struct OldLdapBruteForceFields {
            source: String,
            src_addr: IpAddr,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
            user_pw_list: Vec<(String, String)>,
            start_time: DateTime<Utc>,
            last_time: DateTime<Utc>,
        }

        let value = OldLdapBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            user_pw_list: vec![("user_name".to_string(), "".to_string())],
            start_time: time,
            last_time: time,
        };

        let message = EventMessage {
            time,
            kind: EventKind::LdapBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_12_to_0_16(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_16_to_0_20() {
        use crate::{EventKind, EventMessage};
        use chrono::Utc;
        use serde::{Deserialize, Serialize};
        use std::net::IpAddr;

        let settings = TestSchema::new();
        #[derive(Deserialize, Serialize)]
        struct OldBlockListKerberosFields {
            pub source: String,
            pub src_addr: IpAddr,
            pub src_port: u16,
            pub dst_addr: IpAddr,
            pub dst_port: u16,
            pub proto: u8,
            pub last_time: i64,
            pub request_type: String,
            pub client: String,
            pub service: String,
            pub success: String,
            pub error_msg: String,
            pub from: i64,
            pub till: i64,
            pub cipher: String,
            pub forwardable: String,
            pub renewable: String,
            pub client_cert_subject: String,
            pub server_cert_subject: String,
        }

        let time = Utc::now();
        let value = OldBlockListKerberosFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            src_port: 40000,
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            last_time: time.timestamp_nanos_opt().unwrap_or_default(),
            request_type: "req_type".to_string(),
            client: "client".to_string(),
            service: "service".to_string(),
            success: "tf".to_string(),
            error_msg: "err_msg".to_string(),
            from: 3000,
            till: 1000,
            cipher: "cipher".to_string(),
            forwardable: "forwardable".to_string(),
            renewable: "renewable".to_string(),
            client_cert_subject: "client_cert".to_string(),
            server_cert_subject: "server_cert".to_string(),
        };

        let message = EventMessage {
            time,
            kind: EventKind::BlockListKerberos,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_16_to_0_20(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_20_to_0_22() {
        type PortNumber = u16;
        use crate::collections::Indexed;
        use crate::Indexable;
        use bincode::Options;
        use chrono::{DateTime, Utc};
        use ipnet::Ipv4Net;
        use serde::{Deserialize, Serialize};
        use std::collections::HashMap;
        use std::net::IpAddr;
        use std::net::Ipv4Addr;

        #[derive(Deserialize, Serialize, Clone)]
        struct Nic {
            name: String,
            interface: Ipv4Net,
            gateway: IpAddr,
        }

        #[derive(Deserialize, Serialize, Clone)]
        struct OldNode {
            id: u32,
            name: String,
            customer_id: u32,
            description: String,
            hostname: String,
            nics: Vec<Nic>,                         // abandoned in new Node
            disk_usage_limit: Option<f32>,          // abandoned in new Node
            allow_access_from: Option<Vec<IpAddr>>, // abandoned in new Node
            review_id: Option<u32>,                 // abandoned in new Node
            ssh_port: PortNumber,                   // abandoned in new Node
            dns_server_ip: Option<IpAddr>,          // abandoned in new Node
            dns_server_port: Option<PortNumber>,    // abandoned in new Node
            syslog_server_ip: Option<IpAddr>,       // abandoned in new Node
            syslog_server_port: Option<PortNumber>, // abandoned in new Node
            review: bool,
            review_nics: Option<Vec<String>>, // abandoned in new Node
            review_port: Option<PortNumber>,
            review_web_port: Option<PortNumber>,
            ntp_server_ip: Option<IpAddr>, // abandoned in new Node
            ntp_server_port: Option<PortNumber>, // abandoned in new Node
            piglet: bool,
            giganto: bool,
            giganto_ingestion_nics: Option<Vec<String>>, // replaced with `giganto_ingestion_ip`
            giganto_ingestion_port: Option<PortNumber>,
            giganto_publish_nics: Option<Vec<String>>, // replaced with `giganto_publish_ip`
            giganto_publish_port: Option<PortNumber>,
            giganto_graphql_nics: Option<Vec<String>>, // replaced with `giganto_graphql_ip`
            giganto_graphql_port: Option<PortNumber>,
            reconverge: bool,
            hog: bool,
            creation_time: DateTime<Utc>,
        }

        impl Indexable for OldNode {
            fn key(&self) -> &[u8] {
                self.name.as_bytes()
            }

            fn value(&self) -> Vec<u8> {
                bincode::DefaultOptions::new()
                    .serialize(self)
                    .expect("serializable")
            }

            fn set_index(&mut self, index: u32) {
                self.id = index;
            }
        }

        let settings = TestSchema::new();
        let node_db = settings.store.node_map();
        let old_node = OldNode {
            id: 0,
            name: "node-name".to_string(),
            customer_id: 42,
            description: "description".to_string(),
            hostname: "test-node-host".to_string(),
            nics: vec![
                Nic {
                    name: "eth1".to_string(),
                    interface: "10.1.1.1/32".parse().unwrap(),
                    gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                },
                Nic {
                    name: "eth12".to_string(),
                    interface: "10.1.1.12/32".parse().unwrap(),
                    gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                },
            ],
            disk_usage_limit: Some(100.0),
            allow_access_from: Some(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]),
            review_id: Some(123),
            ssh_port: 22,
            dns_server_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            dns_server_port: Some(53),
            syslog_server_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            syslog_server_port: Some(514),
            review: true,
            review_nics: Some(vec!["eth1".to_string()]),
            review_port: Some(8080),
            review_web_port: Some(8443),
            ntp_server_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            ntp_server_port: Some(123),
            piglet: true,
            giganto: true,
            giganto_ingestion_nics: Some(vec!["eth11".to_string()]),
            giganto_ingestion_port: Some(9090),
            giganto_publish_nics: Some(vec!["eth12".to_string()]),
            giganto_publish_port: Some(9191),
            giganto_graphql_nics: Some(vec!["eth13".to_string()]),
            giganto_graphql_port: Some(9292),
            reconverge: false,
            hog: false,
            creation_time: Utc::now(),
        };
        assert!(node_db.insert(old_node.clone()).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_20_to_0_22(&settings.store).is_ok());

        let node_db = settings.store.node_map();

        let new_value = node_db.get_by_key(old_node.key()).unwrap().unwrap();

        let new_node = bincode::DefaultOptions::new()
            .deserialize::<Node>(new_value.as_ref())
            .unwrap();

        assert_eq!(new_node.id, old_node.id);
        assert_eq!(new_node.name, old_node.name);
        assert_eq!(new_node.customer_id, old_node.customer_id);
        assert_eq!(new_node.description, old_node.description);
        assert_eq!(new_node.hostname, old_node.hostname);
        assert_eq!(new_node.review, old_node.review);
        assert_eq!(new_node.review_port, old_node.review_port);
        assert_eq!(new_node.review_web_port, old_node.review_web_port);
        assert_eq!(new_node.piglet, old_node.piglet);
        assert_eq!(new_node.piglet_giganto_ip, None);
        assert_eq!(new_node.piglet_giganto_port, None);
        assert_eq!(new_node.piglet_review_ip, None);
        assert_eq!(new_node.piglet_review_port, None);
        assert_eq!(new_node.save_packets, false);
        assert_eq!(new_node.http, false);
        assert_eq!(new_node.office, false);
        assert_eq!(new_node.exe, false);
        assert_eq!(new_node.pdf, false);
        assert_eq!(new_node.html, false);
        assert_eq!(new_node.txt, false);
        assert_eq!(new_node.smtp_eml, false);
        assert_eq!(new_node.ftp, false);
        assert_eq!(new_node.giganto, old_node.giganto);
        assert_eq!(new_node.giganto_ingestion_ip, None);
        assert_eq!(
            new_node.giganto_ingestion_port,
            old_node.giganto_ingestion_port
        );
        assert_eq!(
            new_node.giganto_publish_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 12)))
        );
        assert_eq!(new_node.giganto_publish_port, old_node.giganto_publish_port);
        assert_eq!(new_node.giganto_graphql_ip, None);
        assert_eq!(new_node.giganto_graphql_port, old_node.giganto_graphql_port);
        assert_eq!(new_node.retention_period, None);
        assert_eq!(new_node.reconverge, old_node.reconverge);
        assert_eq!(new_node.reconverge_review_ip, None);
        assert_eq!(new_node.reconverge_review_port, None);
        assert_eq!(new_node.reconverge_giganto_ip, None);
        assert_eq!(new_node.reconverge_giganto_port, None);
        assert_eq!(new_node.hog, old_node.hog);
        assert_eq!(new_node.hog_review_ip, None);
        assert_eq!(new_node.hog_review_port, None);
        assert_eq!(new_node.hog_giganto_ip, None);
        assert_eq!(new_node.hog_giganto_port, None);
        assert_eq!(new_node.protocols, false);
        assert_eq!(new_node.protocol_list, HashMap::new());
        assert_eq!(new_node.sensors, false);
        assert_eq!(new_node.sensor_list, HashMap::new());
        assert_eq!(new_node.creation_time, old_node.creation_time);
    }
}
