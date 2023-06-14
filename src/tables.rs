mod accounts;

use crate::types::Account;

use super::{event, IndexedMap, IndexedMultimap, IndexedSet, Map};
use anyhow::Result;
use std::path::{Path, PathBuf};

// Key-value map names in `Database`.
pub(super) const ACCESS_TOKENS: &str = "access_tokens";
pub(super) const ACCOUNTS: &str = "accounts";
pub(super) const ACCOUNT_POLICY: &str = "account policy";
pub(super) const ALLOW_NETWORKS: &str = "allow networks";
pub(super) const BLOCK_NETWORKS: &str = "block networks";
pub(super) const CUSTOMERS: &str = "customers";
pub(super) const DATA_SOURCES: &str = "data sources";
pub(super) const FILTERS: &str = "filters";
pub(super) const MODEL_INDICATORS: &str = "model indicators";
const META: &str = "meta";
pub(super) const NETWORKS: &str = "networks";
pub(super) const NODES: &str = "nodes";
pub(super) const OUTLIERS: &str = "outliers";
pub(super) const SAMPLING_POLICY: &str = "sampling policy";
pub(super) const TEMPLATES: &str = "templates";
pub(super) const TIDB: &str = "TI database";
pub(super) const TOR_EXIT_NODES: &str = "Tor exit nodes";
pub(super) const TRAFFIC_FILTER_RULES: &str = "traffic filter rules";
pub(super) const TRIAGE_POLICY: &str = "triage policy";
pub(super) const TRIAGE_RESPONSE: &str = "triage response";
pub(super) const TRUSTED_DNS_SERVERS: &str = "trusted DNS servers";

const MAP_NAMES: [&str; 21] = [
    ACCESS_TOKENS,
    ACCOUNTS,
    ACCOUNT_POLICY,
    ALLOW_NETWORKS,
    BLOCK_NETWORKS,
    CUSTOMERS,
    DATA_SOURCES,
    FILTERS,
    MODEL_INDICATORS,
    META,
    NETWORKS,
    NODES,
    OUTLIERS,
    SAMPLING_POLICY,
    TEMPLATES,
    TIDB,
    TOR_EXIT_NODES,
    TRAFFIC_FILTER_RULES,
    TRIAGE_POLICY,
    TRIAGE_RESPONSE,
    TRUSTED_DNS_SERVERS,
];

// Keys for the meta map.
pub(super) const EVENT_TAGS: &[u8] = b"event tags";
pub(super) const NETWORK_TAGS: &[u8] = b"network tags";
pub(super) const WORKFLOW_TAGS: &[u8] = b"workflow tags";

#[allow(clippy::module_name_repetitions)]
pub(crate) struct StateDb {
    inner: Option<rocksdb::OptimisticTransactionDB>,
    backup: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path, backup: PathBuf) -> Result<Self, anyhow::Error> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, path, MAP_NAMES)?;

        Ok(Self {
            inner: Some(db),
            backup,
        })
    }

    #[must_use]
    pub(crate) fn accounts(&self) -> Table<Account> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Account>::open(inner).expect("accounts table must be present")
    }

    #[must_use]
    pub fn events(&self) -> event::EventDb {
        let inner = self.inner.as_ref().expect("database must be open");
        event::EventDb::new(inner)
    }

    #[must_use]
    pub(super) fn map(&self, name: &str) -> Option<Map> {
        let inner = self.inner.as_ref().expect("database must be open");
        Map::open(inner, name)
    }

    #[must_use]
    pub(super) fn indexed_map(&self, name: &str) -> Option<IndexedMap> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedMap::new(inner, name).ok()
    }

    #[must_use]
    pub(super) fn indexed_multimap(&self, name: &str) -> Option<IndexedMultimap> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedMultimap::new(inner, name).ok()
    }

    #[must_use]
    pub(super) fn indexed_set(&self, name: &'static [u8]) -> Option<IndexedSet> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedSet::new(inner, META, name).ok()
    }

    pub(super) fn create_new_backup_flush(
        &mut self,
        flush: bool,
        num_of_backups_to_keep: u32,
    ) -> Result<()> {
        let backup = self.backup.as_path();
        let opts = rocksdb::backup::BackupEngineOptions::new(backup)?;
        let db_env = rocksdb::Env::new()?;
        let mut engine = rocksdb::backup::BackupEngine::open(&opts, &db_env)?;
        let inner = self.inner.as_ref().expect("database must be open");
        engine.create_new_backup_flush(inner, flush)?;
        engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .or_else(|_| self.reboot())
    }

    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        let backup = self.backup.as_path();
        let opts = rocksdb::backup::BackupEngineOptions::new(backup)?;
        let db_env = rocksdb::Env::new()?;
        let mut engine = rocksdb::backup::BackupEngine::open(&opts, &db_env)?;

        let opts = rocksdb::backup::RestoreOptions::default();

        let inner = self.inner.as_ref().expect("database must be open");
        inner.cancel_all_background_work(true);
        engine.restore_from_latest_backup(inner.path(), inner.path(), &opts)?;

        self.reboot()
    }

    pub fn restore_from_backup(&mut self, id: u32) -> Result<()> {
        let backup = self.backup.as_path();
        let opts = rocksdb::backup::BackupEngineOptions::new(backup)?;
        let db_env = rocksdb::Env::new()?;
        let mut engine = rocksdb::backup::BackupEngine::open(&opts, &db_env)?;

        let opts = rocksdb::backup::RestoreOptions::default();

        let inner = self.inner.as_ref().expect("database must be open");
        inner.cancel_all_background_work(true);
        engine.restore_from_backup(inner.path(), inner.path(), &opts, id)?;

        self.reboot()
    }

    pub fn get_backup_info(&self) -> Result<Vec<rocksdb::backup::BackupEngineInfo>> {
        let backup = self.backup.as_path();
        let opts = rocksdb::backup::BackupEngineOptions::new(backup)?;
        let db_env = rocksdb::Env::new()?;
        let engine = rocksdb::backup::BackupEngine::open(&opts, &db_env)?;

        Ok(engine.get_backup_info())
    }

    pub fn purge_old_backups(&mut self, num_of_backups_to_keep: u32) -> Result<()> {
        let backup = self.backup.as_path();
        let opts = rocksdb::backup::BackupEngineOptions::new(backup)?;
        let db_env = rocksdb::Env::new()?;
        let mut engine = rocksdb::backup::BackupEngine::open(&opts, &db_env)?;

        if engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .is_err()
        {
            self.reboot()?;
        }
        Ok(())
    }

    fn reboot(&mut self) -> Result<()> {
        let path = self
            .inner
            .as_ref()
            .expect("database must be open")
            .path()
            .to_owned();
        self.close();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, path, MAP_NAMES)?;

        self.inner = Some(db);
        Ok(())
    }

    fn close(&mut self) {
        self.inner = None;
    }
}

/// A database table storing records of type `R`.
pub struct Table<'d, R> {
    map: Map<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> Table<'d, R> {
    fn new(map: Map<'d>) -> Self {
        Self {
            map,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// An iterator over the records in a table.
pub struct TableIter<'i, R> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
    _phantom: std::marker::PhantomData<R>,
}

impl<'i, R> TableIter<'i, R> {
    fn new(
        inner: rocksdb::DBIteratorWithThreadMode<
            'i,
            rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
        >,
    ) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}
