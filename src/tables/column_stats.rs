use anyhow::Result;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use structured::{Description, NLargestCount};

use crate::tables::TableIter;
use crate::types::FromKeyValue;
use crate::{Iterable, UniqueKey, tables::Value as ValueTrait};

use crate::{Map, Table};

impl<'d> Table<'d, ColumnStats> {
    /// Opens the `column_stats` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::COLUMN_STATS).map(Table::new)
    }

    #[must_use]
    pub fn get(&self, model_id: i32, batch_ts: i64, cluster_id: u32) -> TableIter<'_, ColumnStats> {
        let key = Key {
            model_id,
            batch_ts,
            cluster_id,
            column_index: 0,
        };
        let prefix = key.to_bytes();
        self.prefix_iter(Direction::Forward, None, &prefix[..prefix.len() - 4])
    }

    /// # Errors
    ///
    /// Returns an error if the `entry` key is invalid or the database operation fails.
    pub fn remove(&self, entry: &ColumnStats) -> Result<()> {
        self.map.delete(&entry.unique_key())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColumnStats {
    pub model_id: i32,
    pub batch_ts: i64,
    pub cluster_id: u32,
    pub column_index: u32,
    pub description: Description,
    pub n_largest_count: NLargestCount,
}

impl FromKeyValue for ColumnStats {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key);

        let value: Value = super::deserialize(value)?;

        Ok(Self {
            model_id: key.model_id,
            batch_ts: key.batch_ts,
            cluster_id: key.cluster_id,
            column_index: key.column_index,
            description: value.description,
            n_largest_count: value.n_largest_count,
        })
    }
}

impl UniqueKey for ColumnStats {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let capacity = size_of::<i32>() + size_of::<i64>() + size_of::<u32>() * 2;

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.batch_ts.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.column_index.to_be_bytes());

        buf
    }
}

impl ValueTrait for ColumnStats {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            description: self.description.clone(),
            n_largest_count: self.n_largest_count.clone(),
        })
        .expect("serializable")
    }
}

struct Key {
    pub model_id: i32,
    pub batch_ts: i64,
    pub cluster_id: u32,
    pub column_index: u32,
}
impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<i32>() + size_of::<i64>() + size_of::<u32>() * 2;

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.batch_ts.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.column_index.to_be_bytes());
        buf
    }

    ///  # Errors
    ///
    /// Returns an error if deserialization from bytes fails.
    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<i32>());

        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(val);
        let model_id = i32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let batch_ts = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let cluster_id = u32::from_be_bytes(buf);

        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(rest);
        let column_index = u32::from_be_bytes(buf);

        Self {
            model_id,
            batch_ts,
            cluster_id,
            column_index,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    pub description: Description,
    pub n_largest_count: NLargestCount,
}
