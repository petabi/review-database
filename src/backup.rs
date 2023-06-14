//! Database backup utilities.

use crate::Store;
use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

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
            timestamp: Utc.timestamp_nanos(backup.timestamp),
            size: backup.size,
        }
    }
}

/// Schedules periodic database backups.
#[allow(clippy::module_name_repetitions)]
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
            _ = stop.notified() => {
                info!("creating a database backup before shutdown");
                let _res = create(&store, false, backups_to_keep);
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
pub async fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    tracing::error!("database backing up started");
    let mut store = store.write().await;
    if let Err(e) = store.backup(flush, backups_to_keep) {
        drop(store);
        warn!("database backup failed: {:?}", e);
        return Err(e);
    }
    drop(store);
    tracing::error!("database backup created");
    Ok(())
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
pub async fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let store = store.read().await;
    let backup_list = match store.get_backup_info() {
        Ok(backup) => backup,
        Err(e) => {
            drop(store);
            warn!("failed to generate backup list: {:?}", e);
            return Err(e);
        }
    };
    let backup_list: Vec<BackupInfo> = backup_list
        .into_iter()
        .map(std::convert::Into::into)
        .collect();
    info!("generate database backup list");
    Ok(backup_list)
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    tracing::error!("database restore started");
    let mut store = store.write().await;
    let res = match &backup_id {
        Some(id) => store.restore_from_backup(*id),
        None => store.restore_from_latest_backup(),
    };
    drop(store);

    match res {
        Ok(_) => {
            tracing::error!("database restored from backup {:?}", backup_id);
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                "failed to restore database from backup {:?}: {:?}",
                backup_id,
                e
            );
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
