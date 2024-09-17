//! Database backup utilities.

use std::{path::Path, sync::Arc};

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;
use tokio::sync::RwLock;

use crate::{data::MODELS, Store};

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

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
pub async fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store.write().await;
    store.backup(flush, backups_to_keep)
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
pub async fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let backup_list = {
        let store = store.read().await;
        store.get_backup_info()?
    };
    Ok(backup_list
        .into_iter()
        .map(std::convert::Into::into)
        .collect())
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
pub async fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store.write().await;
    match &backup_id {
        Some(id) => store.restore_from_backup(*id),
        None => store.restore_from_latest_backup(),
    }
}

impl Store {
    /// Backs up the current database and keeps the most recent
    /// `num_backups_to_keep` backups.
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub(crate) fn backup(&mut self, flush: bool, num_of_backups_to_keep: u32) -> Result<()> {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };

        fs::create_dir_all(&self.backup_path)?;

        let start = SystemTime::now();
        let mut timestamp = start.duration_since(UNIX_EPOCH)?.as_secs();

        // List all existing backup files and find the greatest timestamp
        let mut backup_files = vec![];
        let mut greatest_timestamp = 0;
        for entry in fs::read_dir(&self.backup_path)? {
            let entry = entry?;
            if let Some(file_name) = entry.file_name().to_str() {
                if let Some(suffix) = file_name.strip_prefix("backup-") {
                    if let Ok(existing_timestamp) = suffix.parse::<u64>() {
                        backup_files.push((existing_timestamp, entry.path()));
                        if existing_timestamp > greatest_timestamp {
                            greatest_timestamp = existing_timestamp;
                        }
                    }
                }
            }
        }

        // Ensure the new timestamp is greater than the greatest existing timestamp
        if timestamp <= greatest_timestamp {
            timestamp = greatest_timestamp + 1;
        }

        let new_backup_file = format!("backup-{timestamp}");
        let new_backup_path = Path::new(&self.backup_path).join(new_backup_file);
        self.states.snapshot(&MODELS, &new_backup_path)?;

        // Sort backup files by timestamp in decreasing order
        backup_files.sort_by_key(|k| std::cmp::Reverse(k.0));

        // Delete old backups if the number of backups exceeds num_of_backups_to_keep
        while backup_files.len() > num_of_backups_to_keep as usize {
            if let Some((_, path)) = backup_files.pop() {
                fs::remove_file(path)?;
            }
        }

        self.legacy_states
            .create_new_backup_flush(flush, num_of_backups_to_keep)
    }

    /// Get the backup information for backups on file.
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn get_backup_info(&self) -> Result<Vec<BackupEngineInfo>> {
        self.legacy_states.get_backup_info()
    }

    /// Restore from the backup with `backup_id` on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails or restoration fails.
    pub fn restore_from_backup(&mut self, backup_id: u32) -> Result<()> {
        self.legacy_states.restore_from_backup(backup_id)
    }

    /// Restore from the latest backup on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails or restoration fails.
    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        self.legacy_states.restore_from_latest_backup()
    }

    /// Purge old backups and only keep `num_backups_to_keep` backups on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn purge_old_backups(&mut self, num_backups_to_keep: u32) -> Result<()> {
        self.legacy_states.purge_old_backups(num_backups_to_keep)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use bincode::Options;
    use chrono::Utc;

    use crate::{event::DnsEventFields, EventKind, EventMessage, Store};

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
            category: crate::EventCategory::CommandAndControl,
        };
        EventMessage {
            time: Utc::now(),
            kind: EventKind::DnsCovertChannel,
            fields: codec.serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn db_backup_list() {
        use tokio::sync::RwLock;

        use crate::backup::list;

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
