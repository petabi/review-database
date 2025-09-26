//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

mod migrate_classifiers_to_filesystem;
mod migrate_cluster;
mod migrate_model;
mod migrate_time_series;

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tracing::info;

/// The range of versions that use the current database format.
///
/// The range should include all the earlier, released versions that use the
/// current database format, and exclude the first future version that uses a
/// new database format.
///
/// # Examples
///
/// ```rust
/// // [Case 1: Stable Patch Version, No Format Change]
/// // The current version is 0.4.1 and the database format hasn't been changed
/// // since 0.3.0. This should include future patch versions such as 0.4.2,
/// // 0.4.3, etc. since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=0.3,<0.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 2: Alpha Patch Version, No RocksDB Format Change]
/// // The current version is 3.4.6-alpha.2 and the database format hasn't been
/// // changed since 1.0.0. Future pre-release versions such as 3.4.6-alpha.3
/// // are compatible since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 3: Transition to New Alpha Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to pre-release is 3.5.0-alpha.1, if no
/// // database format change is involved, then compatible version should be
/// // extended to 3.5.0-alpha.1.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<=3.5.0-alpha.1";
/// ```
///
/// ```rust
/// // [Case 4: Transition to Stable Major Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to release is 3.5.0 (stable), if no
/// // database format change is involved, then migration is not needed, while
/// // compatible version should be extended to 3.5.0., including all future
/// // patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 5: Transition from Alpha to Stable Version, No RocksDB Format Change]
/// // The current version is 3.4.5-alpha.3 and the database format hasn't been
/// // changed since 1.0.0. The next version to release is 3.5.0 (stable), with
/// // compatibility extended to future patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 6: Transition to New Alpha Version, RocksDB Format Change]
/// // The current version is 3.4.5 and the database format is changing in
/// // 3.5.0-alpha.1. The compatibility is now restricted to 3.5.0-alpha.1,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.1,<3.5.0-alpha.2";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.1.
/// ```
///
/// ```rust
/// // [Case 7: Transition Between Alpha Versions, RocksDB Format Change]
/// // The current version is 3.5.0-alpha.2 and the database format is changing in
/// // 3.5.0-alpha.3. The compatibility is now restricted to 3.5.0-alpha.3,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.3,<3.5.0-alpha.4";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.3, including prior alpha changes.
///```
///
/// ```rust
/// // [Case 8: Transition from Alpha to Stable Version, RocksDB Format Finalized]
/// // The current version is 3.5.0-alpha.2 and the database format is
/// // finalized in 3.5.0. The compatibility is extended to all 3.5.0 versions,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0,<3.6.0-alpha";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 (last
/// // release that involves database format change) to 3.5.0, including
/// // all alpha changes finalized in 3.5.0.
/// ```
const COMPATIBLE_VERSION_REQ: &str = ">=0.42.0-alpha.1,<0.42.0-alpha.2";

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
    database: &super::Database,
    store: &super::Store,
    data_dir: P,
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

    let path = data_dir.as_ref();
    let file = path.join("VERSION");

    let version = read_version_file(&file)?;

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };

    migrate_classifiers_to_filesystem::run_migration(database).await?;
    if compatible.matches(&version) {
        migrate_time_series::run(database, store).await?;
        migrate_cluster::run(database, store).await?;
        migrate_model::run(database, store).await?;
    }

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
    let migration: Vec<Migration> = vec![(
        VersionReq::parse(">=0.41.0,<0.42.0-alpha.1")?,
        Version::parse("0.42.0-alpha.1")?,
        migrate_0_41_to_0_42,
    )];

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

fn migrate_0_41_to_0_42(store: &super::Store) -> Result<()> {
    migrate_0_41_events(store)?;
    Ok(())
}

fn migrate_0_41_events(store: &super::Store) -> Result<()> {
    use num_traits::FromPrimitive;

    use crate::event::EventKind;

    let event_db = store.events();
    for row in event_db.raw_iter_forward() {
        let (k, v) = row.map_err(|e| anyhow!("Failed to read event: {e}"))?;
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

        // For events with EventCategory field, migrate the category value 0 (Unknown) to None
        // All other event types require migration of their category field
        if needs_category_migration(event_kind) {
            migrate_event_category(&k, &v, &event_db)?;
        }
    }
    Ok(())
}

fn needs_category_migration(event_kind: crate::event::EventKind) -> bool {
    use crate::event::EventKind::{
        BlocklistBootp, BlocklistConn, BlocklistDceRpc, BlocklistDhcp, BlocklistDns, BlocklistFtp,
        BlocklistHttp, BlocklistKerberos, BlocklistLdap, BlocklistMqtt, BlocklistNfs,
        BlocklistNtlm, BlocklistRdp, BlocklistSmb, BlocklistSmtp, BlocklistSsh, BlocklistTls,
        CryptocurrencyMiningPool, DnsCovertChannel, DomainGenerationAlgorithm, ExternalDdos,
        ExtraThreat, FtpBruteForce, FtpPlainText, HttpThreat, LdapBruteForce, LdapPlainText,
        LockyRansomware, MultiHostPortScan, NetworkThreat, NonBrowser, PortScan, RdpBruteForce,
        RepeatedHttpSessions, SuspiciousTlsTraffic, TorConnection, TorConnectionConn,
        WindowsThreat,
    };
    matches!(
        event_kind,
        BlocklistBootp
            | BlocklistConn
            | BlocklistDceRpc
            | BlocklistDhcp
            | BlocklistDns
            | BlocklistFtp
            | BlocklistHttp
            | BlocklistKerberos
            | BlocklistLdap
            | BlocklistMqtt
            | BlocklistNfs
            | BlocklistNtlm
            | BlocklistRdp
            | BlocklistSmb
            | BlocklistSmtp
            | BlocklistSsh
            | BlocklistTls
            | CryptocurrencyMiningPool
            | DnsCovertChannel
            | DomainGenerationAlgorithm
            | ExternalDdos
            | ExtraThreat
            | FtpBruteForce
            | FtpPlainText
            | HttpThreat
            | LdapBruteForce
            | LdapPlainText
            | LockyRansomware
            | MultiHostPortScan
            | NetworkThreat
            | NonBrowser
            | PortScan
            | RdpBruteForce
            | RepeatedHttpSessions
            | SuspiciousTlsTraffic
            | TorConnection
            | TorConnectionConn
            | WindowsThreat
    )
}

fn migrate_event_category(k: &[u8], v: &[u8], event_db: &crate::EventDb) -> Result<()> {
    use num_traits::FromPrimitive;

    use crate::event::{
        BlocklistBootpFieldsV0_41, BlocklistBootpFieldsV0_42, BlocklistConnFieldsV0_41,
        BlocklistConnFieldsV0_42, BlocklistDceRpcFieldsV0_41, BlocklistDceRpcFieldsV0_42,
        BlocklistDhcpFieldsV0_41, BlocklistDhcpFieldsV0_42, BlocklistDnsFieldsV0_41,
        BlocklistDnsFieldsV0_42, BlocklistHttpFieldsV0_41, BlocklistHttpFieldsV0_42,
        BlocklistKerberosFieldsV0_41, BlocklistKerberosFieldsV0_42, BlocklistMqttFieldsV0_41,
        BlocklistMqttFieldsV0_42, BlocklistNfsFieldsV0_41, BlocklistNfsFieldsV0_42,
        BlocklistNtlmFieldsV0_41, BlocklistNtlmFieldsV0_42, BlocklistRdpFieldsV0_41,
        BlocklistRdpFieldsV0_42, BlocklistSmbFieldsV0_41, BlocklistSmbFieldsV0_42,
        BlocklistSmtpFieldsV0_41, BlocklistSmtpFieldsV0_42, BlocklistSshFieldsV0_41,
        BlocklistSshFieldsV0_42, BlocklistTlsFieldsV0_41, BlocklistTlsFieldsV0_42,
        CryptocurrencyMiningPoolFieldsV0_41, CryptocurrencyMiningPoolFieldsV0_42, DgaFieldsV0_41,
        DgaFieldsV0_42, DnsEventFieldsV0_41, DnsEventFieldsV0_42, EventKind,
        ExternalDdosFieldsV0_41, ExternalDdosFieldsV0_42, FtpBruteForceFieldsV0_41,
        FtpBruteForceFieldsV0_42, FtpEventFieldsV0_41, FtpEventFieldsV0_42, HttpEventFieldsV0_41,
        HttpEventFieldsV0_42, HttpThreatFieldsV0_41, HttpThreatFieldsV0_42,
        LdapBruteForceFieldsV0_41, LdapBruteForceFieldsV0_42, LdapEventFieldsV0_39,
        LdapEventFieldsV0_42, MultiHostPortScanFieldsV0_41, MultiHostPortScanFieldsV0_42,
        PortScanFieldsV0_41, PortScanFieldsV0_42, RdpBruteForceFieldsV0_41,
        RdpBruteForceFieldsV0_42, RepeatedHttpSessionsFieldsV0_41, RepeatedHttpSessionsFieldsV0_42,
    };

    // For bincode serialization, handle each event type
    let key: [u8; 16] = if let Ok(key) = k.try_into() {
        key
    } else {
        return Ok(());
    };
    let key = i128::from_be_bytes(key);
    let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;

    #[allow(clippy::match_same_arms)]
    match EventKind::from_i128(kind_num) {
        Some(EventKind::BlocklistBootp) => {
            migrate_event::<BlocklistBootpFieldsV0_41, BlocklistBootpFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistConn) => {
            migrate_event::<BlocklistConnFieldsV0_41, BlocklistConnFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistDceRpc) => {
            migrate_event::<BlocklistDceRpcFieldsV0_41, BlocklistDceRpcFieldsV0_42>(
                k, v, event_db,
            )?;
        }
        Some(EventKind::BlocklistDhcp) => {
            migrate_event::<BlocklistDhcpFieldsV0_41, BlocklistDhcpFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistDns) => {
            migrate_event::<BlocklistDnsFieldsV0_41, BlocklistDnsFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistFtp) => {
            migrate_event::<FtpEventFieldsV0_41, FtpEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistHttp) => {
            migrate_event::<BlocklistHttpFieldsV0_41, BlocklistHttpFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistKerberos) => {
            migrate_event::<BlocklistKerberosFieldsV0_41, BlocklistKerberosFieldsV0_42>(
                k, v, event_db,
            )?;
        }
        Some(EventKind::BlocklistLdap) => {
            migrate_event::<LdapEventFieldsV0_39, LdapEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistMqtt) => {
            migrate_event::<BlocklistMqttFieldsV0_41, BlocklistMqttFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistNfs) => {
            migrate_event::<BlocklistNfsFieldsV0_41, BlocklistNfsFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistNtlm) => {
            migrate_event::<BlocklistNtlmFieldsV0_41, BlocklistNtlmFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistRdp) => {
            migrate_event::<BlocklistRdpFieldsV0_41, BlocklistRdpFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistSmb) => {
            migrate_event::<BlocklistSmbFieldsV0_41, BlocklistSmbFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistSmtp) => {
            migrate_event::<BlocklistSmtpFieldsV0_41, BlocklistSmtpFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistSsh) => {
            migrate_event::<BlocklistSshFieldsV0_41, BlocklistSshFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::BlocklistTls) => {
            migrate_event::<BlocklistTlsFieldsV0_41, BlocklistTlsFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::CryptocurrencyMiningPool) => {
            migrate_event::<
                CryptocurrencyMiningPoolFieldsV0_41,
                CryptocurrencyMiningPoolFieldsV0_42,
            >(k, v, event_db)?;
        }
        Some(EventKind::DnsCovertChannel) => {
            migrate_event::<DnsEventFieldsV0_41, DnsEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::DomainGenerationAlgorithm) => {
            migrate_event::<DgaFieldsV0_41, DgaFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::ExternalDdos) => {
            migrate_event::<ExternalDdosFieldsV0_41, ExternalDdosFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::FtpBruteForce) => {
            migrate_event::<FtpBruteForceFieldsV0_41, FtpBruteForceFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::FtpPlainText) => {
            migrate_event::<FtpEventFieldsV0_41, FtpEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::HttpThreat) => {
            migrate_event::<HttpThreatFieldsV0_41, HttpThreatFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::LdapBruteForce) => {
            migrate_event::<LdapBruteForceFieldsV0_41, LdapBruteForceFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::LdapPlainText) => {
            migrate_event::<LdapEventFieldsV0_39, LdapEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::LockyRansomware) => {
            migrate_event::<DnsEventFieldsV0_41, DnsEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::MultiHostPortScan) => {
            migrate_event::<MultiHostPortScanFieldsV0_41, MultiHostPortScanFieldsV0_42>(
                k, v, event_db,
            )?;
        }
        Some(EventKind::NonBrowser) => {
            migrate_event::<HttpEventFieldsV0_41, HttpEventFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::PortScan) => {
            migrate_event::<PortScanFieldsV0_41, PortScanFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::RdpBruteForce) => {
            migrate_event::<RdpBruteForceFieldsV0_41, RdpBruteForceFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::RepeatedHttpSessions) => {
            migrate_event::<RepeatedHttpSessionsFieldsV0_41, RepeatedHttpSessionsFieldsV0_42>(
                k, v, event_db,
            )?;
        }
        Some(EventKind::SuspiciousTlsTraffic) => {
            migrate_event::<BlocklistTlsFieldsV0_41, BlocklistTlsFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::TorConnectionConn) => {
            migrate_event::<BlocklistConnFieldsV0_41, BlocklistConnFieldsV0_42>(k, v, event_db)?;
        }
        Some(EventKind::TorConnection) => {
            migrate_event::<HttpEventFieldsV0_41, HttpEventFieldsV0_42>(k, v, event_db)?;
        }
        // Event types that don't have category fields or no detected events, no migration needed
        Some(EventKind::WindowsThreat | EventKind::NetworkThreat | EventKind::ExtraThreat) => {}
        _ => {}
    }

    Ok(())
}

fn migrate_event<'a, T, K>(k: &[u8], v: &'a [u8], event_db: &crate::EventDb) -> Result<()>
where
    T: Deserialize<'a> + Into<K>,
    K: Serialize,
{
    let from_event =
        bincode::deserialize::<T>(v).map_err(|e| anyhow!("Failed to deserialize event: {e}"))?;
    let to_event: K = from_event.into();
    let new =
        bincode::serialize(&to_event).map_err(|e| anyhow!("Failed to serialize event: {e}"))?;
    event_db.update((k, v), (k, &new))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::{Event, EventKind, EventMessage, Store, event::RecordType};

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
    fn migrate_0_41_to_0_42_events() {
        use std::net::IpAddr;

        use chrono::{DateTime, Duration};

        use crate::event::{
            BlocklistBootpFieldsV0_41, BlocklistConnFieldsV0_41, BlocklistDnsFieldsV0_41,
            DnsEventFieldsV0_41, HttpEventFieldsV0_41, HttpThreatFieldsV0_41,
        };
        use crate::types::{EventCategoryV0_41, EventCategoryV0_42};

        let schema = TestSchema::new();
        let event_db = schema.store.events();
        let mut time = DateTime::UNIX_EPOCH;

        // Test BlocklistBootp migration with non-Unknown category
        time += Duration::minutes(1);
        let bootp_value = BlocklistBootpFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            op: 1,
            htype: 1,
            hops: 1,
            xid: 1,
            ciaddr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            yiaddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            giaddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "test-sname".to_string(),
            file: "test-file".to_string(),
            confidence: 0.5,
            category: EventCategoryV0_41::Reconnaissance,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&bootp_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistBootp migration with Unknown category
        time += Duration::minutes(1);
        let bootp_value_unknown = BlocklistBootpFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            op: 1,
            htype: 1,
            hops: 1,
            xid: 1,
            ciaddr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            yiaddr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            giaddr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "test-sname".to_string(),
            file: "test-file".to_string(),
            confidence: 0.5,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&bootp_value_unknown).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistConn migration with non-Unknown category
        time += Duration::minutes(1);
        let mut conn_value = BlocklistConnFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.3".parse::<IpAddr>().unwrap(),
            src_port: 443,
            dst_addr: "10.0.0.3".parse::<IpAddr>().unwrap(),
            dst_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            service: "https".to_string(),
            orig_bytes: 1024,
            resp_bytes: 2048,
            orig_pkts: 10,
            resp_pkts: 15,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2200,
            confidence: 0.7,
            category: EventCategoryV0_41::CommandAndControl,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&conn_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test TorConnectionConn migration with non-Unknown category
        time += Duration::minutes(1);
        conn_value.category = EventCategoryV0_41::InitialAccess;
        let msg = EventMessage {
            time,
            kind: EventKind::TorConnectionConn,
            fields: bincode::serialize(&conn_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistConn migration with Unknown category
        time += Duration::minutes(1);
        let conn_value_unknown = BlocklistConnFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.4".parse::<IpAddr>().unwrap(),
            src_port: 80,
            dst_addr: "10.0.0.4".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            conn_state: "S0".to_string(),
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            service: "http".to_string(),
            orig_bytes: 0,
            resp_bytes: 0,
            orig_pkts: 1,
            resp_pkts: 0,
            orig_l2_bytes: 60,
            resp_l2_bytes: 0,
            confidence: 0.5,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&conn_value_unknown).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistDns migration
        time += Duration::minutes(1);
        let dns_value = BlocklistDnsFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.5".parse::<IpAddr>().unwrap(),
            src_port: 53,
            dst_addr: "8.8.8.8".parse::<IpAddr>().unwrap(),
            dst_port: 53,
            proto: 17,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            query: "example.com".to_string(),
            answer: vec!["93.184.216.34".to_string()],
            trans_id: 1234,
            rtt: 100,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![3600],
            confidence: 0.9,
            category: EventCategoryV0_41::CommandAndControl,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistDns,
            fields: bincode::serialize(&dns_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test TorConnection migration with Unknown category
        time += Duration::minutes(1);
        let mut tor_conn = HttpEventFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            end_time: DateTime::UNIX_EPOCH,
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/test".to_string(),
            referer: "https://referer.com".to_string(),
            version: "1.1".to_string(),
            user_agent: "test-agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            cookie: "session=123".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            filenames: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            mime_types: vec!["text/plain".to_string(), "application/json".to_string()],
            body: b"test body content".to_vec(),
            state: "active".to_string(),
            confidence: 1.0,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&tor_conn).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test NonBrowser migration
        time += Duration::minutes(1);
        tor_conn.category = EventCategoryV0_41::InitialAccess;
        let msg = EventMessage {
            time,
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&tor_conn).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test HttpThreat migration with Unknown category
        time += Duration::minutes(1);
        let http_threat = HttpThreatFieldsV0_41 {
            time,
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.6".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_addr: "10.0.0.6".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            method: "GET".to_string(),
            host: "malicious.com".to_string(),
            uri: "/malware.exe".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_len: 200,
            response_len: 1200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "application/octet-stream".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: "closed".to_string(),
            db_name: String::new(),
            rule_id: 1001,
            matched_to: "uri".to_string(),
            cluster_id: Some(1),
            attack_kind: "malware".to_string(),
            confidence: 0.95,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&http_threat).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test DnsCovertChannel migration
        time += Duration::minutes(1);
        let mut dns_covert = DnsEventFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            end_time: time + Duration::seconds(1),
            src_addr: "192.168.1.7".parse::<IpAddr>().unwrap(),
            src_port: 54321,
            dst_addr: "8.8.4.4".parse::<IpAddr>().unwrap(),
            dst_port: 53,
            proto: 17,
            query: "suspicious-domain.com".to_string(),
            answer: vec!["1.2.3.4".to_string()],
            trans_id: 5678,
            rtt: 50,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![300],
            confidence: 0.8,
            category: EventCategoryV0_41::Exfiltration,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&dns_covert).unwrap(),
        };

        // Test LockyRansomware migration
        time += Duration::minutes(1);
        dns_covert.category = EventCategoryV0_41::Impact;
        event_db.put(&msg).unwrap();
        let msg = EventMessage {
            time,
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&dns_covert).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Run migration
        super::migrate_0_41_events(&schema.store).unwrap();

        // Verify migrations
        let mut iter = event_db.iter_forward();

        // Verify BlocklistBootp with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Bootp(event)) = event else {
            panic!("expected BlocklistBootp event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Reconnaissance));

        // Verify BlocklistBootp with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Bootp(event)) = event else {
            panic!("expected BlocklistBootp event");
        };
        assert_eq!(event.category, None);

        // Verify BlocklistConn with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Conn(event)) = event else {
            panic!("expected BlocklistConn event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::CommandAndControl));

        // Verify TorConnectionConn
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::TorConnectionConn(event) = event else {
            panic!("expected TorConnectionConn event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::InitialAccess));

        // Verify BlocklistConn with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Conn(event)) = event else {
            panic!("expected BlocklistConn event");
        };
        assert_eq!(event.category, None);

        // Verify BlocklistDns with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Dns(event)) = event else {
            panic!("expected BlocklistDns event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::CommandAndControl));

        // Verify TorConnection with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::TorConnection(event) = event else {
            panic!("expected TorConnection event");
        };
        assert_eq!(event.category, None);

        // Verify NonBrowser with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::NonBrowser(event) = event else {
            panic!("expected NonBrowser event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::InitialAccess));

        // Verify HttpThreat with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::HttpThreat(event) = event else {
            panic!("expected HttpThreat event");
        };
        assert_eq!(event.category, None);

        // Verify DnsCovertChannel with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::DnsCovertChannel(event) = event else {
            panic!("expected DnsCovertChannel event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Exfiltration));

        // Verify LockyRansomware with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::LockyRansomware(event) = event else {
            panic!("expected LockyRansomware event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Impact));
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
}
