use std::collections::HashSet;

use anyhow::Result;
use chrono::NaiveDateTime;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use structured::{Description, Element, NLargestCount};

use crate::tables::TableIter;
use crate::types::FromKeyValue;
use crate::{ColumnStatisticsUpdate, Map, Statistics, Table, TopMultimaps};
use crate::{Iterable, UniqueKey, tables::Value as ValueTrait};

impl<'d> Table<'d, ColumnStats> {
    /// Opens the `column_stats` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::COLUMN_STATS).map(Table::new)
    }

    /// Retrieves a `TableIter` for the `ColumnStats` entries matching the given parameters.
    #[must_use]
    pub fn get(&self, batch_ts: i64, cluster_id: u32) -> TableIter<'_, ColumnStats> {
        let key = Key {
            cluster_id,
            batch_ts,
            column_index: 0,
            model_id: 0,
        };
        let prefix = key.to_bytes();
        self.prefix_iter(
            Direction::Forward,
            None,
            &prefix[..prefix.len() - size_of::<u32>() - size_of::<i32>()],
        )
    }

    /// # Errors
    ///
    /// Returns an error if the `entry` key is invalid or the database operation fails.
    pub fn remove(&self, entry: &ColumnStats) -> Result<()> {
        self.map.delete(&entry.unique_key())
    }

    /// Returns the column statistics for the given cluster and time.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_column_statistics(
        &self,
        cluster: u32,
        time: Vec<NaiveDateTime>,
    ) -> Result<Vec<Statistics>> {
        if time.is_empty() {
            let prefix = cluster.to_be_bytes();
            return self
                .prefix_iter(Direction::Forward, None, &prefix)
                .map(|result| {
                    let column_stats = result?;
                    Ok(Statistics {
                        batch_ts: from_timestamp(column_stats.batch_ts)?,
                        column_index: i32::try_from(column_stats.column_index)?,
                        column_stats: structured::ColumnStatistics {
                            description: column_stats.description,
                            n_largest_count: column_stats.n_largest_count,
                        },
                    })
                })
                .collect();
        }
        time.into_iter()
            .map(from_naive_utc)
            .flat_map(|t| self.get(t, cluster))
            .map(|result: std::result::Result<ColumnStats, anyhow::Error>| {
                let column_stats = result?;
                Ok(Statistics {
                    batch_ts: from_timestamp(column_stats.batch_ts)?,
                    column_index: i32::try_from(column_stats.column_index)?,
                    column_stats: structured::ColumnStatistics {
                        description: column_stats.description,
                        n_largest_count: column_stats.n_largest_count,
                    },
                })
            })
            .collect()
    }

    /// Inserts column statistics into the database.
    ///
    /// # Differences from Postgres version
    /// This function expects `cluster_id` as a `u32`, not a `String`.
    /// Conversion must be handled before calling.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn insert_column_statistics(
        &self,
        statistics: Vec<(u32, ColumnStatisticsUpdate)>,
        model_id: i32,
        batch_ts: NaiveDateTime,
    ) -> Result<()> {
        let batch_ts = from_naive_utc(batch_ts);
        for (cluster_id, columns) in statistics {
            let mut key = Key {
                cluster_id,
                batch_ts,
                column_index: 0,
                model_id,
            };
            for (column_index, col) in columns.column_statistics.into_iter().enumerate() {
                key.column_index = u32::try_from(column_index)?;

                let value = Value {
                    description: col.description,
                    n_largest_count: col.n_largest_count,
                };
                // Insert the serialized value into the map.
                self.map
                    .insert(&key.to_bytes(), &super::serialize(&value)?)?;
            }
        }
        Ok(())
    }

    /// Gets the top N multimaps of a model.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_top_multimaps_of_model(
        &self,
        _model_id: i32,
        _number_of_top_n: usize,
        _min_top_n_of_1_to_n: usize,
        _time: Option<NaiveDateTime>,
    ) -> Result<Vec<TopMultimaps>> {
        todo!("Implement get_top_multimaps_of_model");
        // This function is not implemented yet.
    }

    /// Returns the number of rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count_rounds_by_cluster(&self, cluster_id: i32) -> Result<i64> {
        let prefix = cluster_id.to_be_bytes();
        let iter = self.prefix_iter(Direction::Forward, None, &prefix);
        i64::try_from(
            iter.filter_map(|result| {
                let column_stats = result.ok()?;
                Some(column_stats.batch_ts)
            })
            .collect::<HashSet<_>>()
            .len(),
        )
        .map_err(|_| anyhow::anyhow!("Failed to convert count to i64"))
    }

    /// Returns the rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn load_rounds_by_cluster(
        &self,
        cluster_id: i32,
        after: &Option<NaiveDateTime>,
        before: &Option<NaiveDateTime>,
        is_first: bool,
        limit: usize,
    ) -> Result<(i32, Vec<NaiveDateTime>)> {
        let prefix = cluster_id.to_be_bytes();
        let mut buf = Vec::with_capacity(size_of::<u32>() + size_of::<i64>());
        buf.extend(cluster_id.to_be_bytes());
        let (direction, from) = if is_first {
            if let Some(after) = after {
                let after_ts = from_naive_utc(*after);
                buf.extend(after_ts.to_be_bytes());
                (Direction::Forward, Some(buf.as_slice()))
            } else {
                (Direction::Forward, None)
            }
        } else if let Some(before) = before {
            let before_ts = from_naive_utc(*before);
            buf.extend(before_ts.to_be_bytes());
            (Direction::Reverse, Some(buf.as_slice()))
        } else {
            (Direction::Reverse, None)
        };
        let iter = self.prefix_iter(direction, from, &prefix);
        let mut model_id = Option::None;
        let mut rounds = HashSet::new();
        for (m_id, round) in iter.filter_map(|result| {
            let column_stats = result.ok()?;
            Some((
                column_stats.model_id,
                from_timestamp(column_stats.batch_ts).ok()?,
            ))
        }) {
            if model_id.is_none() {
                model_id = Some(m_id);
            } else if model_id != Some(m_id) {
                return Err(anyhow::anyhow!("Model ID mismatch"));
            }
            rounds.insert(round);
            if rounds.len() >= limit {
                break;
            }
        }
        let model_id = model_id.ok_or_else(|| anyhow::anyhow!("No model ID found"))?;
        Ok((model_id, rounds.into_iter().collect()))
    }

    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_column_types_of_model(
        &self,
        model_id: i32,
    ) -> Result<Vec<crate::StructuredColumnType>> {
        let md_id = model_id.to_be_bytes();
        let mut prefix = None;
        for result in self
            .map
            .db
            .iterator_cf(self.map.cf, rocksdb::IteratorMode::Start)
        {
            let (key, _value) = result?;
            if key.ends_with(&md_id) {
                prefix = Some(key[..key.len() - size_of::<i32>() - size_of::<u32>()].to_vec());
                break;
            }
        }
        if let Some(prefix) = prefix {
            let iter = self.prefix_iter(Direction::Forward, None, &prefix);
            let mut column_types = Vec::new();
            for result in iter {
                let column_stats = result?;
                if column_stats.model_id == model_id {
                    column_types.push(crate::StructuredColumnType::from((
                        i32::try_from(column_stats.column_index)?,
                        get_column_type(&column_stats)
                            .ok_or(anyhow::anyhow!("Unsupported column type"))?,
                    )));
                }
            }
            return Ok(column_types);
        }
        Ok(Vec::new())
    }
}

fn get_column_type(column_stats: &ColumnStats) -> Option<i32> {
    // Determine the column type based on the mode of n_largest_count.
    // This is a simplified mapping; adjust as necessary for your application.
    match &column_stats.n_largest_count.mode() {
        Some(Element::Int(_)) => Some(1),
        Some(Element::Enum(_)) => Some(2),
        Some(Element::FloatRange(_)) => Some(3),
        Some(Element::Text(_)) => Some(4),
        Some(Element::IpAddr(_)) => Some(5),
        Some(Element::DateTime(_)) => Some(6),
        Some(Element::Binary(_)) => Some(7),
        _ => None,
    }
}

fn from_timestamp(timestamp: i64) -> Result<NaiveDateTime> {
    // Convert the timestamp to a NaiveDateTime.
    const A_BILLION: i64 = 1_000_000_000;

    let s = timestamp / A_BILLION;
    let nanos = u32::try_from(timestamp % A_BILLION)?;
    chrono::DateTime::from_timestamp(s, nanos)
        .map(|t| t.naive_utc())
        .ok_or(anyhow::anyhow!("Invalid timestamp: {}", timestamp))
}

fn from_naive_utc(date: NaiveDateTime) -> i64 {
    // Convert a NaiveDateTime to a timestamp in nanoseconds.
    const A_BILLION: i64 = 1_000_000_000;

    let seconds = date.and_utc().timestamp();
    let nanos = i64::from(date.and_utc().timestamp_subsec_nanos());
    seconds * A_BILLION + nanos
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ColumnStats {
    pub cluster_id: u32,
    pub batch_ts: i64,
    pub column_index: u32,
    pub model_id: i32,
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
        Key {
            cluster_id: self.cluster_id,
            batch_ts: self.batch_ts,
            column_index: self.column_index,
            model_id: self.model_id,
        }
        .to_bytes()
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
    pub cluster_id: u32,
    pub batch_ts: i64,
    pub column_index: u32,
    pub model_id: i32,
}
impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<i32>() + size_of::<i64>() + size_of::<u32>() * 2;

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.batch_ts.to_be_bytes());
        buf.extend(self.column_index.to_be_bytes());
        buf.extend(self.model_id.to_be_bytes());
        buf
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let cluster_id = u32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let batch_ts = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let column_index = u32::from_be_bytes(buf);

        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(rest);
        let model_id = i32::from_be_bytes(buf);

        Self {
            cluster_id,
            batch_ts,
            column_index,
            model_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    pub description: Description,
    pub n_largest_count: NLargestCount,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use structured::ElementCount;

    use crate::Store;

    #[test]
    fn test_column_stats() {
        use structured::{Description, NLargestCount};
        let store = setup_store();
        let table = store.column_stats_map();

        let stats = super::ColumnStats {
            cluster_id: 42,
            batch_ts: 1_622_547_800,
            column_index: 0,
            model_id: 1,
            description: Description::default(),
            n_largest_count: NLargestCount::default(),
        };
        table.insert(&stats).unwrap();
        let retrieved = table.get(1_622_547_800, 42).next().unwrap().unwrap();
        assert_eq!(retrieved, stats);
    }

    #[test]
    fn test_insert_and_get_column_statistics() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let store = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 1;
        let model_id = 99;
        let batch_ts = NaiveDate::from_ymd_opt(2023, 6, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let statistics = vec![(
            cluster_id,
            crate::ColumnStatisticsUpdate {
                cluster_id: cluster_id.to_string(),
                column_statistics: vec![ColumnStatistics {
                    description: Description::default(),
                    n_largest_count: NLargestCount::new(
                        2,
                        vec![
                            ElementCount {
                                value: Element::Int(1),
                                count: 10,
                            },
                            ElementCount {
                                value: Element::Int(2),
                                count: 5,
                            },
                        ],
                        Some(Element::Int(1)),
                    ),
                }],
            },
        )];

        table
            .insert_column_statistics(statistics, model_id, batch_ts)
            .unwrap();

        let stats = table
            .get_column_statistics(cluster_id, vec![batch_ts])
            .unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].column_index, 0);
        assert_eq!(
            stats[0].column_stats.n_largest_count.number_of_elements(),
            2
        );
    }

    #[test]
    fn test_count_rounds_by_cluster() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let store = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 11;
        let model_id = 2;

        let batch1 = NaiveDate::from_ymd_opt(2023, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let batch2 = NaiveDate::from_ymd_opt(2023, 2, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats1 = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(42),
                    count: 7,
                }],
                Some(Element::Int(42)),
            ),
        };

        let stats2 = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(83),
                    count: 3,
                }],
                Some(Element::Int(83)),
            ),
        };

        table
            .insert_column_statistics(
                vec![(
                    cluster_id,
                    crate::ColumnStatisticsUpdate {
                        cluster_id: cluster_id.to_string(),
                        column_statistics: vec![stats1],
                    },
                )],
                model_id,
                batch1,
            )
            .unwrap();

        table
            .insert_column_statistics(
                vec![(
                    cluster_id,
                    crate::ColumnStatisticsUpdate {
                        cluster_id: cluster_id.to_string(),
                        column_statistics: vec![stats2],
                    },
                )],
                model_id,
                batch2,
            )
            .unwrap();

        let count = table.count_rounds_by_cluster(cluster_id as i32).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_load_rounds_by_cluster() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let store = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 123;
        let model_id = 42;

        let batch1 = NaiveDate::from_ymd_opt(2024, 1, 10)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let batch2 = NaiveDate::from_ymd_opt(2024, 2, 10)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(5),
                    count: 1,
                }],
                Some(Element::Int(5)),
            ),
        };

        for batch in &[batch1, batch2] {
            table
                .insert_column_statistics(
                    vec![(
                        cluster_id,
                        crate::ColumnStatisticsUpdate {
                            cluster_id: cluster_id.to_string(),
                            column_statistics: vec![stats.clone()],
                        },
                    )],
                    model_id,
                    *batch,
                )
                .unwrap();
        }

        let (retrieved_model_id, rounds) = table
            .load_rounds_by_cluster(cluster_id as i32, &None, &None, true, 10)
            .unwrap();

        assert_eq!(retrieved_model_id, model_id);
        assert_eq!(rounds.len(), 2);
        assert!(rounds.contains(&batch1));
        assert!(rounds.contains(&batch2));
    }

    #[test]
    fn test_get_column_types_of_model() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let store = setup_store();
        let table = store.column_stats_map();

        let model_id = 101;
        let cluster_id = 7;
        let batch_ts = NaiveDate::from_ymd_opt(2023, 3, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::IpAddr("127.0.0.1".parse().unwrap()),
                    count: 1,
                }],
                Some(Element::IpAddr("127.0.0.1".parse().unwrap())),
            ),
        };

        table
            .insert_column_statistics(
                vec![(
                    cluster_id,
                    crate::ColumnStatisticsUpdate {
                        cluster_id: cluster_id.to_string(),
                        column_statistics: vec![stats],
                    },
                )],
                model_id,
                batch_ts,
            )
            .unwrap();

        let column_types = table.get_column_types_of_model(model_id).unwrap();
        assert_eq!(column_types.len(), 1);
        assert_eq!(column_types[0].column_index, 0);
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }
}
