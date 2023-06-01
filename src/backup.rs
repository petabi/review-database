//! Database backup utilities.
mod postgresql;

#[allow(clippy::module_name_repetitions)]
pub use self::postgresql::BackupConfig;
use self::postgresql::{create_backup_path, purge_old_postgres_backups};
use crate::{
    backup::postgresql::{postgres_backup, postgres_backup_list, postgres_restore},
    Store,
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, RwLock};
use tracing::info;

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct BackupInfo {
    pub id: u32,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
}

impl From<BackupEngineInfo> for BackupInfo {
    fn from(backup: BackupEngineInfo) -> Self {
        Self {
            id: backup.backup_id,
            timestamp: Utc
                .timestamp_opt(backup.timestamp, 0)
                .single()
                .expect("Invalid timestamp value"),
            size: backup.size,
        }
    }
}

/// Schedules periodic database backups.
#[allow(clippy::module_name_repetitions)]
pub async fn schedule_periodic(
    store: Arc<RwLock<Store>>,
    backup_cfg: Arc<RwLock<BackupConfig>>,
    schedule: (Duration, Duration),
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
                let _res = create(&store, false, &backup_cfg);
            }
            _ = stop.notified() => {
                let _res = create(&store, false, &backup_cfg);
                stop.notify_one();
                return;
            }

        }
    }
}

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
pub async fn create(
    store: &Arc<RwLock<Store>>,
    flush: bool,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<()> {
    info!("backing up database...");
    {
        let num_of_backups = { backup_cfg.read().await.num_of_backups };
        let mut backup_store = store.write().await;
        if let Err(e) = backup_store.backup(flush, num_of_backups) {
            return Err(anyhow!("failed to create key-value database backup: {e:?}"));
        }
    }

    let backup_id_list = backup_id_list(store).await?;
    let backup_cfg = backup_cfg.read().await;
    if let Err(e) = postgres_backup(&backup_cfg, backup_id_list) {
        return Err(anyhow!(
            "failed to create relational database backup: {e:?}"
        ));
    }
    Ok(())
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
pub async fn list(
    store: &Arc<RwLock<Store>>,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<Vec<BackupInfo>> {
    let res = {
        let store = store.read().await;
        store.get_backup_info()
    };
    let mut backup_list: Vec<BackupInfo> = match res {
        Ok(backup_list) => {
            info!("generate database backup list");
            backup_list
                .into_iter()
                .map(std::convert::Into::into)
                .collect()
        }
        Err(e) => {
            return Err(anyhow!("failed to generate key-value backup list: {e:?}"));
        }
    };

    let backup_cfg = &backup_cfg.read().await;
    if let Err(e) = postgres_backup_list(&backup_cfg.backup_path, &mut backup_list) {
        return Err(anyhow!(
            "failed to add list information from a relational database: {e:?}"
        ));
    }
    Ok(backup_list)
}

/// Restores the database from a backup. If a backup file ID is not provided,
/// restore based on the latest backup.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn restore(
    store: &Arc<RwLock<Store>>,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
    backup_id: Option<u32>,
) -> Result<u32> {
    let backup_id_list = backup_id_list(store).await?;
    let backup_id = if let Some(id) = backup_id {
        if !backup_id_list.contains(&id) {
            return Err(anyhow!("backup {id} is not exist"));
        }
        info!("start database restore {}", id);
        id
    } else {
        let Some(id) = backup_id_list.last() else {
            return Err(anyhow!("backup is not exist"));
        };
        info!("start database restore from latest backup");
        *id
    };

    let res = {
        let mut store = store.write().await;
        store.restore_from_backup(backup_id)
    };
    if let Err(e) = res {
        return Err(anyhow!(
            "failed to restore key-value database from {backup_id}: {e:?}"
        ));
    }

    let backup_cfg = backup_cfg.read().await;
    if let Err(e) = postgres_restore(&backup_cfg, backup_id) {
        return Err(anyhow!(
            "failed to restore relational database from {backup_id}: {e:?}"
        ));
    }
    Ok(backup_id)
}

/// Returns the number of backups in the backup list.
///
/// # Errors
///
/// Returns an error if getting the number of backup lists fails.
pub async fn count(store: &Arc<RwLock<Store>>) -> Result<usize> {
    let store = store.write().await;
    Ok(store.get_backup_info()?.len())
}

/// Remove older backups based on the number of backups retained.
///
/// # Errors
///
/// Returns an error if removing old backup fails.
pub async fn purge_old_backups(
    store: &Arc<RwLock<Store>>,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<()> {
    {
        let num_of_backups = { backup_cfg.read().await.num_of_backups };
        let mut backup_store = store.write().await;
        if let Err(e) = backup_store.purge_old_backups(num_of_backups) {
            return Err(anyhow!("failed to purge key-value database: {e:?}"));
        }
    }

    let backup_id_list = backup_id_list(store).await?;
    let data_backup_path = {
        let cfg = backup_cfg.read().await;
        create_backup_path(&cfg)?
    };
    if let Err(e) = purge_old_postgres_backups(&data_backup_path, backup_id_list) {
        return Err(anyhow!("failed to purge relational database: {e:?}"));
    }
    Ok(())
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn recover(
    store: &Arc<RwLock<Store>>,
    backup_cfg: &Arc<RwLock<BackupConfig>>,
) -> Result<u32> {
    info!("recovering database from latest valid backup");

    let res = {
        let mut store = store.write().await;
        store.recover()
    };
    let recovery_id = match res {
        Ok(id) => id,
        Err(e) => {
            return Err(anyhow!(
                "failed to recover key-value database from backup: {e:?}"
            ));
        }
    };

    let backup_cfg = backup_cfg.read().await;
    if let Err(e) = postgres_restore(&backup_cfg, recovery_id) {
        return Err(anyhow!(
            "failed to recover relational database from backup {e:?}"
        ));
    }
    Ok(recovery_id)
}

/// Lists the backup id.
///
/// # Errors
///
/// Returns an error if backup id list fails to create
#[allow(clippy::module_name_repetitions)]
pub async fn backup_id_list(store: &Arc<RwLock<Store>>) -> Result<Vec<u32>> {
    let store = store.read().await;
    match store.get_backup_info() {
        Ok(backup) => Ok(backup.into_iter().map(|b| b.backup_id).collect()),
        Err(e) => Err(anyhow!("failed to generate backup id list: {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::{backup::BackupConfig, event::DnsEventFields, EventKind, EventMessage, Store};
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

        let backup_cfg = BackupConfig::builder()
            .backup_path(backup_dir.path())
            .build();
        let backup_cfg = Arc::new(RwLock::new(backup_cfg));
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
        let backup_list = list(&store, &backup_cfg).await.unwrap();
        assert_eq!(backup_list.len(), 3);
        assert_eq!(backup_list.get(0).unwrap().id, 1);
        assert_eq!(backup_list.get(1).unwrap().id, 2);
        assert_eq!(backup_list.get(2).unwrap().id, 3);
    }
}
