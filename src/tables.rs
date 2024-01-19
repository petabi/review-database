mod accounts;
mod batch_info;
mod category;
mod qualifier;
mod scores;
mod status;

use crate::{
    batch_info::BatchInfo, category::Category, qualifier::Qualifier, scores::Scores,
    status::Status, types::Account, Indexable,
};

use super::{event, Indexed, IndexedMap, IndexedMultimap, IndexedSet, Map};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// Key-value map names in `Database`.
pub(super) const ACCESS_TOKENS: &str = "access_tokens";
pub(super) const ACCOUNTS: &str = "accounts";
pub(super) const ACCOUNT_POLICY: &str = "account policy";
pub(super) const ALLOW_NETWORKS: &str = "allow networks";
pub(super) const BATCH_INFO: &str = "batch_info";
pub(super) const BLOCK_NETWORKS: &str = "block networks";
pub(super) const CATEGORY: &str = "category";
pub(super) const CUSTOMERS: &str = "customers";
pub(super) const DATA_SOURCES: &str = "data sources";
pub(super) const FILTERS: &str = "filters";
pub(super) const MODEL_INDICATORS: &str = "model indicators";
const META: &str = "meta";
pub(super) const NETWORKS: &str = "networks";
pub(super) const NODES: &str = "nodes";
pub(super) const OUTLIERS: &str = "outliers";
pub(super) const QUALIFIERS: &str = "qualifiers";
pub(super) const SAMPLING_POLICY: &str = "sampling policy";
pub(super) const SCORES: &str = "scores";
pub(super) const STATUSES: &str = "statuses";
pub(super) const TEMPLATES: &str = "templates";
pub(super) const TIDB: &str = "TI database";
pub(super) const TOR_EXIT_NODES: &str = "Tor exit nodes";
pub(super) const TRAFFIC_FILTER_RULES: &str = "traffic filter rules";
pub(super) const TRIAGE_POLICY: &str = "triage policy";
pub(super) const TRIAGE_RESPONSE: &str = "triage response";
pub(super) const TRUSTED_DNS_SERVERS: &str = "trusted DNS servers";
pub(super) const TRUSTED_USER_AGENTS: &str = "trusted user agents";

const MAP_NAMES: [&str; 27] = [
    ACCESS_TOKENS,
    ACCOUNTS,
    ACCOUNT_POLICY,
    ALLOW_NETWORKS,
    BATCH_INFO,
    BLOCK_NETWORKS,
    CATEGORY,
    CUSTOMERS,
    DATA_SOURCES,
    FILTERS,
    MODEL_INDICATORS,
    META,
    NETWORKS,
    NODES,
    OUTLIERS,
    QUALIFIERS,
    SAMPLING_POLICY,
    SCORES,
    STATUSES,
    TEMPLATES,
    TIDB,
    TOR_EXIT_NODES,
    TRAFFIC_FILTER_RULES,
    TRIAGE_POLICY,
    TRIAGE_RESPONSE,
    TRUSTED_DNS_SERVERS,
    TRUSTED_USER_AGENTS,
];

// Keys for the meta map.
pub(super) const EVENT_TAGS: &[u8] = b"event tags";
pub(super) const NETWORK_TAGS: &[u8] = b"network tags";
pub(super) const WORKFLOW_TAGS: &[u8] = b"workflow tags";

#[allow(clippy::module_name_repetitions)]
pub(crate) struct StateDb {
    inner: Option<rocksdb::OptimisticTransactionDB>,
    backup: PathBuf,
    db: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path, backup: PathBuf) -> Result<Self> {
        Self::try_open(path.to_owned(), backup, false)
    }

    fn try_open(path: PathBuf, backup: PathBuf, recover_on_fail: bool) -> Result<Self> {
        let db = match Self::open_db(&path) {
            Ok(db) => db,
            Err(e) => {
                if recover_on_fail {
                    tracing::warn!("fail to open db {e:?}");
                    tracing::warn!("recovering from latest backup available");

                    Self::recover_db(&path, &backup)?
                } else {
                    return Err(e);
                }
            }
        };

        Ok(Self {
            inner: Some(db),
            backup,
            db: path,
        })
    }

    #[must_use]
    pub(crate) fn accounts(&self) -> Table<Account> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Account>::open(inner).expect("accounts table must be present")
    }

    #[must_use]
    pub(crate) fn batch_info(&self) -> Table<BatchInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<BatchInfo>::open(inner).expect("accounts table must be present")
    }

    #[must_use]
    pub(crate) fn scores(&self) -> Table<Scores> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Scores>::open(inner).expect("accounts table must be present")
    }

    #[must_use]
    pub(crate) fn categories(&self) -> IndexedTable<Category> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Category>::open(inner).expect("category table must be present")
    }

    #[must_use]
    pub(crate) fn qualifiers(&self) -> IndexedTable<Qualifier> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Qualifier>::open(inner).expect("category table must be present")
    }

    #[must_use]
    pub(crate) fn statuses(&self) -> IndexedTable<Status> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Status>::open(inner).expect("category table must be present")
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
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let inner = self
            .inner
            .as_ref()
            .ok_or(anyhow!("unable to backup, database has closed"))?;
        engine.create_new_backup_flush(inner, flush)?;

        engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .or_else(|_| self.reboot())
    }

    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let mut opts = rocksdb::backup::RestoreOptions::default();
        opts.set_keep_log_files(true);

        self.close();

        engine.restore_from_latest_backup(&self.db, &self.db, &opts)?;

        self.reboot()
    }

    pub fn restore_from_backup(&mut self, id: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let opts = rocksdb::backup::RestoreOptions::default();

        self.close();

        engine.restore_from_backup(&self.db, &self.db, &opts, id)?;

        self.reboot()
    }

    pub fn get_backup_info(&self) -> Result<Vec<rocksdb::backup::BackupEngineInfo>> {
        let engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        Ok(engine.get_backup_info())
    }

    pub fn purge_old_backups(&mut self, num_of_backups_to_keep: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        if engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .is_err()
        {
            self.reboot()?;
        }
        Ok(())
    }

    pub fn recover(&mut self) -> Result<()> {
        self.close();

        let db = Self::recover_db(&self.db, &self.backup)?;
        self.inner = Some(db);
        Ok(())
    }

    fn close(&mut self) {
        if let Some(db) = self.inner.as_ref() {
            db.cancel_all_background_work(true);
        }
        self.inner = None;
    }

    fn reboot(&mut self) -> Result<()> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, &self.db, MAP_NAMES)?;

        self.inner = Some(db);
        Ok(())
    }

    fn open_db(path: &Path) -> Result<rocksdb::OptimisticTransactionDB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        Ok(rocksdb::OptimisticTransactionDB::open_cf(
            &opts, path, MAP_NAMES,
        )?)
    }

    fn recover_db(path: &Path, backup: &Path) -> Result<rocksdb::OptimisticTransactionDB> {
        let mut engine = open_rocksdb_backup_engine(backup)?;
        let available = engine.get_backup_info();
        let restore_opts = rocksdb::backup::RestoreOptions::default();
        for backup_id in available.into_iter().rev().map(|b| b.backup_id) {
            match engine.restore_from_backup(path, path, &restore_opts, backup_id) {
                Ok(()) => match Self::open_db(path) {
                    Ok(db) => {
                        tracing::info!("restored from backup (id: {backup_id})");
                        return Ok(db);
                    }
                    Err(e) => {
                        tracing::warn!("opening restored backup (id: {backup_id}) failed {e:?}");
                    }
                },
                Err(e) => {
                    tracing::error!("restoring backup (id: {backup_id}) failed {e:?}");
                }
            }
        }
        Err(anyhow!(
            "unable to recover from backups available at: {}",
            backup.display()
        ))
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

pub struct IndexedTable<'d, R: Indexable> {
    indexed_map: IndexedMap<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> IndexedTable<'d, R>
where
    R: Indexable,
{
    fn new(indexed_map: IndexedMap<'d>) -> Self {
        Self {
            indexed_map,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns the number of entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the map index is not found or the database operation fails.    
    pub fn count(&self) -> Result<usize> {
        self.indexed_map.count()
    }

    /// Removes a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, id: u32) -> Result<Vec<u8>> {
        self.indexed_map.remove(id)
    }

    /// Deactivates a key-value pair with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn deactivate(&self, id: u32) -> Result<Vec<u8>> {
        self.indexed_map.deactivate(id)
    }
}

pub trait Key {
    type Output<'a>
    where
        Self: 'a;
    fn key(&self) -> Self::Output<'_>;
}

pub trait Value {
    type Output<'a>
    where
        Self: 'a;
    fn value(&self) -> Self::Output<'_>;
}

fn serialize<I: Serialize>(input: &I) -> anyhow::Result<Vec<u8>> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().serialize(input)?)
}

fn deserialize<'de, O: Deserialize<'de>>(input: &'de [u8]) -> anyhow::Result<O> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().deserialize(input)?)
}

/// Opens a RocksDB backup engine using the default options and environment.
fn open_rocksdb_backup_engine(
    path: &Path,
) -> Result<rocksdb::backup::BackupEngine, rocksdb::Error> {
    let opts = rocksdb::backup::BackupEngineOptions::new(path)?;
    let db_env = rocksdb::Env::new()?;
    rocksdb::backup::BackupEngine::open(&opts, &db_env)
}
