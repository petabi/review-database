//! The `filter` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{types::FromKeyValue, FilterEndpoint, FlowKind, LearningMethod, Map, Table};

#[derive(Default)]
pub struct Filter {
    pub username: String,
    pub name: String,
    pub directions: Option<Vec<FlowKind>>,
    pub keywords: Option<Vec<String>>,
    pub network_tags: Option<Vec<String>>,
    pub customers: Option<Vec<String>>,
    pub endpoints: Option<Vec<FilterEndpoint>>,
    pub sensors: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
    pub devices: Option<Vec<String>>,
    pub host_names: Option<Vec<String>>,
    pub user_ids: Option<Vec<String>>,
    pub user_names: Option<Vec<String>>,
    pub user_departments: Option<Vec<String>>,
    pub countries: Option<Vec<String>>,
    pub categories: Option<Vec<u8>>,
    pub levels: Option<Vec<u8>>,
    pub kinds: Option<Vec<String>>,
    pub learning_methods: Option<Vec<LearningMethod>>,
    pub confidence: Option<f32>,
}

impl Filter {
    fn create_key(username: &str, name: &str) -> Vec<u8> {
        let mut key = username.as_bytes().to_owned();
        key.push(0);
        key.extend(name.as_bytes());
        key
    }

    fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = Filter::create_key(&self.username, &self.name);
        let value = Value {
            directions: self.directions,
            keywords: self.keywords,
            network_tags: self.network_tags,
            customers: self.customers,
            endpoints: self.endpoints,
            sensors: self.sensors,
            os: self.os,
            devices: self.devices,
            host_names: self.host_names,
            user_ids: self.user_ids,
            user_names: self.user_names,
            user_departments: self.user_departments,
            countries: self.countries,
            categories: self.categories,
            levels: self.levels,
            kinds: self.kinds,
            learning_methods: self.learning_methods,
            confidence: self.confidence,
        };
        let value = super::serialize(&value)?;
        Ok((key, value))
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Value {
    directions: Option<Vec<FlowKind>>,
    keywords: Option<Vec<String>>,
    network_tags: Option<Vec<String>>,
    customers: Option<Vec<String>>,
    endpoints: Option<Vec<FilterEndpoint>>,
    sensors: Option<Vec<String>>,
    os: Option<Vec<String>>,
    devices: Option<Vec<String>>,
    host_names: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    categories: Option<Vec<u8>>,
    levels: Option<Vec<u8>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence: Option<f32>,
}

impl FromKeyValue for Filter {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let sep = key
            .iter()
            .position(|c| *c == 0)
            .ok_or(anyhow!("corruptted access token"))?;
        let username = std::str::from_utf8(&key[..sep])?.to_string();
        let name = std::str::from_utf8(&key[sep + 1..])?.to_string();
        let value: Value = super::deserialize(value)?;
        Ok(Self {
            username,
            name,
            directions: value.directions,
            keywords: value.keywords,
            network_tags: value.network_tags,
            customers: value.customers,
            endpoints: value.endpoints,
            sensors: value.sensors,
            os: value.os,
            devices: value.devices,
            host_names: value.host_names,
            user_ids: value.user_ids,
            user_names: value.user_names,
            user_departments: value.user_departments,
            countries: value.countries,
            categories: value.categories,
            levels: value.levels,
            kinds: value.kinds,
            learning_methods: value.learning_methods,
            confidence: value.confidence,
        })
    }
}

/// Functions for the `filter` map.
impl<'d> Table<'d, Filter> {
    /// Opens the  `filter` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::FILTERS).map(Table::new)
    }

    /// Inserts `Filter` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, filter: Filter) -> Result<()> {
        let (key, value) = filter.into_key_value()?;
        self.map.insert(&key, &value)
    }

    /// Removes `Filter` with given `username` and `name` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn remove<'a>(&self, username: &str, filters: impl Iterator<Item = &'a str>) -> Result<()> {
        for filter in filters {
            let key = Filter::create_key(username, filter);
            self.map.delete(&key)?;
        }
        Ok(())
    }

    /// Finds `Filter` with given `username` `name` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get(&self, username: &str, name: &str) -> Result<Option<Filter>> {
        let key = Filter::create_key(username, name);

        self.map
            .get(&key)?
            .map(|v| Filter::from_key_value(&key, v.as_ref()))
            .transpose()
    }

    /// Lists `Filter`(s) with given `username` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn list(&self, username: &str) -> Result<Vec<Filter>> {
        use rocksdb::{Direction::Forward, IteratorMode::From};
        let prefix = username.as_bytes();
        let iter = self
            .map
            .inner_prefix_iterator(From(prefix, Forward), prefix);
        iter.map(|(k, v)| Filter::from_key_value(&k, &v))
            .filter_map(|filter| {
                filter
                    .map(|f| {
                        if f.username == username {
                            Some(f)
                        } else {
                            None
                        }
                    })
                    .transpose()
            })
            .collect()
    }

    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{Filter, Store};

    #[test]
    fn operations() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.filter_map();

        let tester = &[("bbb", "f2"), ("aaa", "f1"), ("bb", "f1"), ("aaaa", "f2")];
        for (username, name) in tester {
            let mut filter = Filter::default();
            filter.username = username.to_string();
            filter.name = name.to_string();

            assert!(table.insert(filter).is_ok());
        }

        for (username, name) in tester {
            let mut filter = Filter::default();
            filter.username = username.to_string();
            filter.name = name.to_string();

            assert!(table.insert(filter).is_err());
        }

        for (username, name) in tester {
            let res = table.list(username).unwrap();
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].username, *username);
            assert_eq!(res[0].name, *name);

            let res = table.get(username, name).unwrap();
            assert!(res.is_some());
            let filter = res.unwrap();
            assert_eq!(filter.username, *username);
            assert_eq!(filter.name, *name);
        }

        for (username, name) in tester {
            assert!(table.remove(username, vec![*name].into_iter()).is_ok());
        }
    }
}
