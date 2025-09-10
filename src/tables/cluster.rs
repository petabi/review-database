use std::mem::size_of;

use anyhow::{Result, anyhow, bail};
use chrono::NaiveDateTime;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use crate::{
    Iterable, Map, Table, UniqueKey, tables::TableIter, tables::Value as ValueTrait,
    types::FromKeyValue,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Cluster {
    model_id: i32,
    id: i32,
    category_id: i32,
    detector_id: i32,
    event_ids: Vec<i64>,
    sensors: Vec<String>,
    labels: Option<Vec<String>>,
    qualifier_id: i32,
    status_id: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    last_modification_time: Option<NaiveDateTime>,
}

impl<'d> Table<'d, Cluster> {
    /// Opens the `cluster` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CLUSTER).map(Table::new)
    }

    /// Counts the number of clusters matching the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn count_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
    ) -> Result<usize> {
        let prefix = model.to_be_bytes();
        let iter = self.prefix_iter(Direction::Forward, None, &prefix);

        Ok(filter_cluster(iter, categories, detectors, qualifiers, statuses).count())
    }

    /// Updates the cluster with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn update_cluster(
        &self,
        model_id: i32,
        id: i32,
        category: Option<i32>,
        qualifier: Option<i32>,
        status: Option<i32>,
    ) -> Result<()> {
        if category.is_none() && qualifier.is_none() && status.is_none() {
            return Err(anyhow!("no update fields provided"));
        }

        let key = Key {
            model_id,
            cluster_id: id,
        }
        .to_bytes();
        let Some(value) = self.map.get(&key)? else {
            bail!("cluster with model_id {} and id {} not found", model_id, id)
        };
        let mut entry: Cluster = FromKeyValue::from_key_value(&key, value.as_ref())?;
        if let Some(category) = category {
            entry.category_id = category;
        }
        if let Some(qualifier) = qualifier {
            entry.qualifier_id = qualifier;
        }
        if let Some(status) = status {
            entry.status_id = status;
        }

        entry.last_modification_time = Some(chrono::Utc::now().naive_utc());
        self.put(&entry)
    }

    /// Updates the clusters with the given cluster IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn update_clusters(
        &self,
        updates: Vec<crate::UpdateClusterRequest>,
        model_id: i32,
    ) -> Result<()> {
        let txn = self.map.db.transaction();
        let now = chrono::Utc::now().naive_utc();
        for update in updates {
            let key = Key {
                model_id,
                cluster_id: update.cluster_id,
            }
            .to_bytes();
            let (event_ids, sensors) = update.event_ids.into_iter().fold(
                (Vec::new(), Vec::new()),
                |(mut ts, mut src), id| {
                    ts.push(id.0);
                    src.push(id.1);
                    (ts, src)
                },
            );

            let Some(value) = self.map.get(&key)? else {
                let entry = Cluster {
                    model_id,
                    id: update.cluster_id,
                    category_id: 1, // default to "Uncategorized"
                    detector_id: update.detector_id,
                    event_ids,
                    sensors,
                    labels: update.labels,
                    qualifier_id: 1, // default to "Unqualified"
                    status_id: update.status_id,
                    signature: update.signature,
                    size: update.size,
                    score: update.score,
                    last_modification_time: Some(now),
                };
                self.insert_with_transaction(&entry, &txn)?;
                continue;
            };
            let mut entry: Cluster = FromKeyValue::from_key_value(&key, value.as_ref())?;

            entry.status_id = update.status_id;

            entry.event_ids.extend_from_slice(&event_ids);
            entry.event_ids.sort_unstable();
            entry.event_ids.dedup();

            entry.sensors.extend_from_slice(&sensors);
            entry.sensors.sort_unstable();
            entry.sensors.dedup();

            if let Some(labels) = update.labels {
                entry.labels = Some(labels);
            }

            entry.signature = update.signature;

            entry.size += update.size;

            if let Some(score) = update.score {
                entry.score = Some(score);
            }
            entry.last_modification_time = Some(now);
            self.put_with_transaction(&entry, &txn)?;
        }
        Ok(txn.commit()?)
    }

    /// Returns the clusters that satisfy the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn load_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Cluster>> {
        let prefix = model.to_be_bytes();
        let direction = Direction::Forward;
        let iter = self.prefix_iter(direction, None, &prefix);
        let mut clusters = filter_cluster(iter, categories, detectors, qualifiers, statuses)
            .filter(|c| {
                if let Some((id, size)) = after
                    && is_first
                {
                    return c.size < *size || (c.id < *id && c.size == *size);
                }
                if let Some((id, size)) = before
                    && !is_first
                {
                    return c.size > *size || (c.id > *id && c.size == *size);
                }
                true
            })
            .take(limit)
            .collect::<Vec<_>>();
        if is_first {
            clusters.sort_unstable_by_key(|c| (std::cmp::Reverse(c.size), std::cmp::Reverse(c.id)));
        } else {
            clusters.sort_unstable_by_key(|c| (c.size, c.id));
        }
        Ok(clusters)
    }
}

fn filter_cluster(
    iter: TableIter<'_, Cluster>,
    categories: Option<&[i32]>,
    detectors: Option<&[i32]>,
    qualifiers: Option<&[i32]>,
    statuses: Option<&[i32]>,
) -> impl Iterator<Item = Cluster> {
    iter.filter_map(move |res| {
        let cluster = res.ok()?;
        if let Some(categories) = categories
            && !categories.contains(&cluster.category_id)
        {
            return None;
        }
        if let Some(detectors) = detectors
            && !detectors.contains(&cluster.detector_id)
        {
            return None;
        }
        if let Some(qualifiers) = qualifiers
            && !qualifiers.contains(&cluster.qualifier_id)
        {
            return None;
        }
        if let Some(statuses) = statuses
            && !statuses.contains(&cluster.status_id)
        {
            return None;
        }
        Some(cluster)
    })
}

#[derive(Deserialize, Serialize)]
struct Value {
    category_id: i32,
    detector_id: i32,
    event_ids: Vec<i64>,
    sensors: Vec<String>,
    labels: Option<Vec<String>>,
    qualifier_id: i32,
    status_id: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    last_modification_time: Option<NaiveDateTime>,
}

impl ValueTrait for Cluster {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            category_id: self.category_id,
            detector_id: self.detector_id,
            event_ids: self.event_ids.clone(),
            sensors: self.sensors.clone(),
            labels: self.labels.clone(),
            qualifier_id: self.qualifier_id,
            status_id: self.status_id,
            signature: self.signature.clone(),
            size: self.size,
            score: self.score,
            last_modification_time: self.last_modification_time,
        })
        .expect("serializable")
    }
}
struct Key {
    model_id: i32,
    cluster_id: i32,
}

impl FromKeyValue for Cluster {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key);

        let value: Value = super::deserialize(value)?;

        Ok(Self {
            model_id: key.model_id,
            id: key.cluster_id,
            category_id: value.category_id,
            detector_id: value.detector_id,
            event_ids: value.event_ids,
            sensors: value.sensors,
            labels: value.labels,
            qualifier_id: value.qualifier_id,
            status_id: value.status_id,
            signature: value.signature,
            size: value.size,
            score: value.score,
            last_modification_time: value.last_modification_time,
        })
    }
}

impl UniqueKey for Cluster {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            model_id: self.model_id,
            cluster_id: self.id,
        }
        .to_bytes()
    }
}

impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<i32>() * 2;

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());

        buf
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<i32>());
        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(val);
        let model_id = i32::from_be_bytes(buf);

        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(rest);
        let cluster_id = i32::from_be_bytes(buf);

        Self {
            model_id,
            cluster_id,
        }
    }
}
