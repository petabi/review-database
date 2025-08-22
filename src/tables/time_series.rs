use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table, UniqueKey, tables::Value, types::FromKeyValue};

impl<'d> Table<'d, TimeSeries> {
    /// Opens the `time_series` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TIME_SERIES).map(Table::new)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TimeSeries {
    pub cluster_id: i32,
    pub time: i64, // batch_ts
    pub value: i64,
    pub count_index: Option<i32>, // column index
    pub count: i64,
}

impl UniqueKey for TimeSeries {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            cluster_id: self.cluster_id,
            time: self.time,
            value: self.value,
            count_index: self.count_index,
        }
        .to_bytes()
    }
}

impl Value for TimeSeries {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        self.count.to_be_bytes().to_vec()
    }
}

impl FromKeyValue for TimeSeries {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_bytes(key);

        let value = i64::from_be_bytes(value.try_into()?);

        Ok(Self {
            cluster_id: key.cluster_id,
            time: key.time,
            value: key.value,
            count_index: key.count_index,
            count: value,
        })
    }
}

struct Key {
    cluster_id: i32,
    time: i64,
    value: i64,
    count_index: Option<i32>,
}

impl Key {
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.time.to_be_bytes());
        buf.extend(self.value.to_be_bytes());
        if let Some(count_index) = self.count_index {
            buf.extend(count_index.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<i32>());
        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(val);
        let cluster_id = i32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let time = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        buf.copy_from_slice(val);
        let value = i64::from_be_bytes(buf);

        let mut buf = [0; size_of::<i32>()];
        let count_index = if rest.is_empty() {
            None
        } else {
            buf.copy_from_slice(rest);
            Some(i32::from_be_bytes(buf))
        };

        Self {
            cluster_id,
            time,
            value,
            count_index,
        }
    }
}
