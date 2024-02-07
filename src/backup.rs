//! Database backup utilities.
#![allow(clippy::module_name_repetitions)]
mod postgres;

pub use self::postgres::BackupConfig;
use self::postgres::{backup_list, backup_list_len};
use crate::{
    backup::postgres::{create_postgres_backup, DEFAULT_ZIP_EXTENSION},
    Store, DEFAULT_STATES,
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;
use std::{fs::File, io::Write};
use std::{sync::Arc, time::Duration};
use tempfile::tempdir_in;
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

pub struct BackupInfo {
    pub id: u32,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
}

impl From<BackupEngineInfo> for BackupInfo {
    fn from(backup: BackupEngineInfo) -> Self {
        Self {
            id: backup.backup_id,
            timestamp: Utc.timestamp_nanos(backup.timestamp),
            size: backup.size,
        }
    }
}

/// Schedules periodic database backups.
pub async fn schedule_periodic(
    store: Arc<RwLock<Store>>,
    schedule: (Duration, Duration),
    backups_to_keep: u32,
    stop: Arc<Notify>,
) {
    use tokio::time::{sleep, Instant};

    let (init, duration) = schedule;
    let sleep = sleep(init);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            () = &mut sleep => {
                sleep.as_mut().reset(Instant::now() + duration);
                let _res = create(&store, false, backups_to_keep);
            }
            () = stop.notified() => {
                info!("creating a database backup before shutdown");
                let _res = create(&store, false, backups_to_keep);
                stop.notify_one();
                return;
            }

        }
    }
}

pub struct ArchiveBackupInfo {
    pub file_name: String,
    pub file_size: u64,
    pub creation_time: DateTime<Utc>,
}

/// Create a compressed backup file of rocksdb and postgres.
///
/// # Errors
///
/// Returns an error if backup fails.
pub async fn create_archive_backup(
    store: &Arc<RwLock<Store>>,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<String> {
    info!("backing up database...");

    // backup file/folder name
    let current_backup_name = Local::now().format("%Y%m%d_%H%M%S").to_string();

    // mkdir temporary folder (specify a path that can cover a large capacity)
    let backup_path = { backup_cfg.read().await.backup_path.clone() };
    let temp_dir = tempdir_in(&backup_path)?;
    let Some(temp_dir_path) = temp_dir.path().to_str() else {
        return Err(anyhow!("Backup temporary folder creation failed"));
    };
    let temp_backup_path = format!("{temp_dir_path}/{current_backup_name}");
    if std::fs::create_dir(&temp_backup_path).is_err() {
        return Err(anyhow!("Backup temporary folder creation failed"));
    }

    // backup rocksdb
    {
        // create version file
        let file = format!("{temp_backup_path}/VERSION");
        let mut f = File::create(&file).context("cannot create VERSION")?;
        f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
            .context("cannot write VERSION")?;

        // create backup
        let rocksdb_backup_path = format!("{temp_backup_path}/{DEFAULT_STATES}");
        let mut store = store.write().await;
        if let Err(e) = store.backup_from_check_point(std::path::Path::new(&rocksdb_backup_path)) {
            return Err(anyhow!("failed to create key-value database backup: {e:?}"));
        }
    }

    // backup postgres
    {
        let backup_cfg = backup_cfg.read().await;
        if let Err(e) = create_postgres_backup(&backup_cfg, &temp_backup_path) {
            return Err(anyhow!(
                "failed to create relational database backup: {e:?}"
            ));
        }
    }

    // make two database backup zipped file
    let zip_file_name = format!("{current_backup_name}.{DEFAULT_ZIP_EXTENSION}");
    let zip_path = format!("/{}/{zip_file_name}", backup_path.to_string_lossy());
    let env_path = { backup_cfg.read().await.env_path.clone() };

    tokio::spawn(async move {
        // Move the ownership of the temp_dir so that it is not dropped until the compress operation is finished.
        let temp_dir = temp_dir;
        if let Some(temp_dir_path) = temp_dir.path().to_str() {
            if let Err(e) = self::postgres::run_command(
                "tar",
                &env_path,
                &["czf", &zip_path, "-C", temp_dir_path, &current_backup_name],
            ) {
                warn!("database backup failed: {:?}", e);
            } else {
                info!("backing up database completed");
            }
        }
    });

    Ok(zip_file_name)
}

/// Lists the backup information for the compressed backup files.
///
/// # Errors
///
/// Returns an error if backup list fails to create
pub async fn list_archived_files(
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<Vec<ArchiveBackupInfo>> {
    let backup_path = { backup_cfg.read().await.backup_path.clone() };
    backup_list(&backup_path)
}

/// Returns the number of backups in the backup list.
///
/// # Errors
///
/// Returns an error if getting the number of backup lists fails.
pub async fn count(backup_cfg: &Arc<RwLock<BackupConfig>>) -> usize {
    let backup_path = { backup_cfg.read().await.backup_path.clone() };
    backup_list_len(&backup_path)
}

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
pub async fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    info!("backing up database...");
    let res = {
        let mut store = store.write().await;
        store.backup(flush, backups_to_keep)
    };
    match res {
        Ok(()) => {
            info!("backing up database completed");
            Ok(())
        }
        Err(e) => {
            warn!("database backup failed: {:?}", e);
            Err(e)
        }
    }
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
pub async fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let res = {
        let store = store.read().await;
        store.get_backup_info()
    };
    match res {
        Ok(backup_list) => {
            info!("generate database backup list");
            Ok(backup_list
                .into_iter()
                .map(std::convert::Into::into)
                .collect())
        }
        Err(e) => {
            warn!("failed to generate backup list: {:?}", e);
            Err(e)
        }
    }
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    info!("restoring database from {:?}", backup_id);
    let res = {
        let mut store = store.write().await;
        match &backup_id {
            Some(id) => store.restore_from_backup(*id),
            None => store.restore_from_latest_backup(),
        }
    };

    match res {
        Ok(()) => {
            info!("database restored from backup {:?}", backup_id);
            Ok(())
        }
        Err(e) => {
            warn!(
                "failed to restore database from backup {:?}: {:?}",
                backup_id, e
            );
            Err(e)
        }
    }
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn recover(store: &Arc<RwLock<Store>>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    info!("recovering database from latest valid backup");
    let res = {
        let mut store = store.write().await;
        store.recover()
    };

    match res {
        Ok(()) => {
            info!("database recovered from backup");
            Ok(())
        }
        Err(e) => {
            warn!("failed to recover database from backup: {e:?}");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{event::DnsEventFields, EventKind, EventMessage, Store};
    use bincode::Options;
    use chrono::Utc;
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
    async fn db_backup_list() {
        use crate::backup::list;
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
        }

        let msg = example_message();

        // backing up 1
        {
            let mut store = store.write().await;
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }
        // backing up 2
        {
            let mut store = store.write().await;
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // backing up 3
        {
            let mut store = store.write().await;
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // get backup list
        let backup_list = list(&store).await.unwrap();
        assert_eq!(backup_list.len(), 3);
        assert_eq!(backup_list.get(0).unwrap().id, 1);
        assert_eq!(backup_list.get(1).unwrap().id, 2);
        assert_eq!(backup_list.get(2).unwrap().id, 3);
    }
}
