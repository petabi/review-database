//! # Test Utilities Module
//!
//! The `test` module provides shared utilities and data structures for
//! conducting unit tests throughout the `review-database` crate. Its primary
//! focus is on facilitating the setup and management of a test database
//! environment, utilizing the `OptimisticTransactionDB` from the `rocksdb`
//! crate. This setup is crucial for tests that require interaction with a
//! database, ensuring they run against a realistic and isolated environment.

use rocksdb::OptimisticTransactionDB;

use crate::collections::IndexedSet;

pub(super) struct Store {
    db: OptimisticTransactionDB,
}

impl Store {
    pub(super) fn new() -> Self {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("test.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, ["test_cf"]).unwrap();
        Self { db }
    }

    pub(super) fn indexed_set(&self) -> IndexedSet<'_> {
        IndexedSet::new(&self.db, "test_cf", b"indexed set").unwrap()
    }
}
