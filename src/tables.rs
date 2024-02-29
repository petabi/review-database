mod access_token;
mod accounts;
mod batch_info;
mod category;
mod csv_column_extra;
mod filter;
mod model_indicator;
mod network;
mod qualifier;
mod scores;
mod status;
mod template;
mod tor_exit_node;
mod triage_response;

use crate::{
    batch_info::BatchInfo,
    category::Category,
    csv_column_extra::CsvColumnExtra,
    scores::Scores,
    types::{Account, FromKeyValue, Qualifier, Status},
    Direction, Indexable,
};

use super::{event, Indexed, IndexedMap, IndexedSet, Map};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

pub use self::access_token::AccessToken;
pub use self::filter::Filter;
pub use self::model_indicator::ModelIndicator;
pub use self::network::{Network, Update as NetworkUpdate};
pub use self::template::{
    Structured, StructuredClusteringAlgorithm, Template, Unstructured,
    UnstructuredClusteringAlgorithm,
};
pub use self::tor_exit_node::TorExitNode;
pub use self::triage_response::{TriageResponse, Update as TriageResponseUpdate};

// Key-value map names in `Database`.
pub(super) const ACCESS_TOKENS: &str = "access_tokens";
pub(super) const ACCOUNTS: &str = "accounts";
pub(super) const ACCOUNT_POLICY: &str = "account policy";
pub(super) const ALLOW_NETWORKS: &str = "allow networks";
pub(super) const BATCH_INFO: &str = "batch_info";
pub(super) const BLOCK_NETWORKS: &str = "block networks";
pub(super) const CATEGORY: &str = "category";
pub(super) const CSV_COLUMN_EXTRAS: &str = "csv column extras";
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

const MAP_NAMES: [&str; 28] = [
    ACCESS_TOKENS,
    ACCOUNTS,
    ACCOUNT_POLICY,
    ALLOW_NETWORKS,
    BATCH_INFO,
    BLOCK_NETWORKS,
    CATEGORY,
    CSV_COLUMN_EXTRAS,
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
        Self::open_db(path).map(|db| Self {
            inner: Some(db),
            backup,
            db: path.to_owned(),
        })
    }

    #[must_use]
    pub(crate) fn access_tokens(&self) -> Table<AccessToken> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<AccessToken>::open(inner).expect("{ACCESS_TOKENS} table must be present")
    }

    #[must_use]
    pub(crate) fn accounts(&self) -> Table<Account> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Account>::open(inner).expect("{ACCOUNTS} table must be present")
    }

    #[must_use]
    pub(crate) fn batch_info(&self) -> Table<BatchInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<BatchInfo>::open(inner).expect("{BATCH_INFO} table must be present")
    }

    #[must_use]
    pub(crate) fn filters(&self) -> Table<Filter> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Filter>::open(inner).expect("{FILTERS} table must be present")
    }

    #[must_use]
    pub(crate) fn model_indicators(&self) -> Table<ModelIndicator> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<ModelIndicator>::open(inner).expect("{MODEL_INDICATORS} table must be present")
    }

    #[must_use]
    pub(crate) fn scores(&self) -> Table<Scores> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Scores>::open(inner).expect("{SCORES} table must be present")
    }

    #[must_use]
    pub(crate) fn templates(&self) -> Table<Template> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Template>::open(inner).expect("{TEMPLATES} table must be present")
    }

    #[must_use]
    pub(crate) fn tor_exit_nodes(&self) -> Table<TorExitNode> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TorExitNode>::open(inner).expect("{TOR_EXIT_NODES} table must be present")
    }

    #[must_use]
    pub(crate) fn categories(&self) -> IndexedTable<Category> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Category>::open(inner).expect("{CATEGORY} table must be present")
    }

    #[must_use]
    pub(crate) fn qualifiers(&self) -> IndexedTable<Qualifier> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Qualifier>::open(inner).expect("{QUALIFIERS} table must be present")
    }

    #[must_use]
    pub(crate) fn statuses(&self) -> IndexedTable<Status> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Status>::open(inner).expect("{STATUSES} table must be present")
    }

    #[must_use]
    pub(crate) fn csv_column_extras(&self) -> IndexedTable<CsvColumnExtra> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<CsvColumnExtra>::open(inner)
            .expect("{CSV_COLUMN_EXTRAS} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_responses(&self) -> IndexedTable<TriageResponse> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriageResponse>::open(inner)
            .expect("{TRIAGE_RESPONSE} table must be present")
    }

    #[must_use]
    pub(crate) fn networks(&self) -> IndexedTable<Network> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Network>::open(inner).expect("{NETWORKS} table must be present")
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
}

/// Represents a table that can be iterated over.
pub trait Iterable<R: FromKeyValue> {
    /// Returns an iterator over the records in the table.
    fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_, R>;
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

impl<'i, R> Iterator for TableIter<'i, R>
where
    R: FromKeyValue,
{
    type Item = Result<R, anyhow::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let serialized_item = self.inner.next()?;
        match serialized_item {
            Ok((mut key, mut value)) => {
                if key.is_empty() {
                    match self.inner.next()? {
                        Ok((k, v)) => {
                            key = k;
                            value = v;
                        }
                        Err(e) => return Some(Err(e.into())),
                    }
                }
                let item = R::from_key_value(&key, &value);
                Some(item.map_err(Into::into))
            }
            Err(e) => Some(Err(e.into())),
        }
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

impl<'d, R: UniqueKey + Value> Table<'d, R> {
    /// Stores a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, record: &R) -> Result<()> {
        self.map.put(&record.unique_key(), &record.value())
    }

    /// Adds a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with the same key exists, or the database
    /// operation fails.
    pub fn insert(&self, record: &R) -> Result<()> {
        self.map.insert(&record.unique_key(), &record.value())
    }
}

impl<R: FromKeyValue> Iterable<R> for Table<'_, R> {
    fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Forward)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::Start)),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Reverse)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::End)),
            },
        }
    }
}

pub struct IndexedTable<'d, R> {
    indexed_map: IndexedMap<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> IndexedTable<'d, R> {
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

    /// Stores a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, entry: R) -> Result<u32>
    where
        R: Indexable,
    {
        self.indexed_map.insert(entry)
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

impl<R: FromKeyValue> Iterable<R> for IndexedTable<'_, R> {
    fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Forward),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::Start),
                ),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Reverse),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::End),
                ),
            },
        }
    }
}

/// Represents entities that can be uniquely identified by a key.
///
/// The `UniqueKey` trait is designed to provide a standardized way to retrieve
/// a unique, opaque key for instances of structs that implement this trait. The
/// key is returned as a `Cow<[u8]>`, allowing for flexible ownership
/// models—--either borrowing from an existing slice or owning the data
/// outright.
///
/// Implementing this trait allows for unique identification of instances, which
/// can be used for indexing, identification in collections, or any scenario
/// where a distinct, non-colliding identifier is necessary.
///
/// # Examples
///
/// ```
/// # use std::borrow::Cow;
/// # use review_database::UniqueKey;
/// struct User {
///     id: u32,
///     username: String,
/// }
///
/// impl UniqueKey for User {
///     fn unique_key(&self) -> Cow<[u8]> {
///         Cow::Owned(self.id.to_be_bytes().to_vec())
///     }
/// }
/// ```
pub trait UniqueKey {
    /// Returns a unique, opaque key for the instance as a `Cow<[u8]>`.
    ///
    /// This method should return a byte slice that uniquely identifies the
    /// instance of the struct. The returned `Cow<[u8]>` allows the key to be
    /// either borrowed or owned, depending on the implementation's needs.
    ///
    /// # Examples
    ///
    /// Using the `UniqueKey` implementation for a `User` struct defined in the
    /// trait-level documentation:
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # struct User { id: u32, username: String }
    /// # impl User {
    /// #     fn unique_key(&self) -> Cow<[u8]> {
    ///         Cow::Owned(self.id.to_be_bytes().to_vec())
    /// #     }
    /// # }
    /// let user = User { id: 1, username: String::from("alice") };
    /// assert_eq!(user.unique_key(), Cow::Borrowed(b"\x00\x00\x00\x01"));
    /// ```
    ///
    /// In this example, the `unique_key` method returns the user's `id` as a
    /// byte array, converted into a `Vec<u8>` and then into a `Cow::Owned`,
    /// providing a unique key for the user instance.
    fn unique_key(&self) -> Cow<[u8]>;
}

impl<R: Indexable> UniqueKey for R {
    fn unique_key(&self) -> Cow<[u8]> {
        self.indexed_key()
    }
}

pub trait Value {
    fn value(&self) -> Cow<[u8]>;
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
