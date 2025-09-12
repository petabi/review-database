use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct Model {
    id: u32,
    name: String,
    version: i32,
    kind: String,
    max_event_id_num: i32,
    data_source_id: i32,
    classification_id: Option<i64>,
}

/// Functions for the `model` indexed map.
impl<'d> IndexedTable<'d, Model> {
    /// Opens the `model` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::MODELS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `Model` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }

    /// Adds a new model to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    pub fn add_model(&self, model: Model) -> Result<u32> {
        self.indexed_map.insert(model)
    }

    /// Deletes the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn delete_model(&self, name: &str) -> Result<u32> {
        let model: Model = self.load_model_by_name(name)?;
        self.remove(model.id)?;
        Ok(model.id)
    }

    /// Returns the number of models.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn count_models(&self) -> Result<usize> {
        self.count()
    }

    /// Returns the model with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn load_model(&self, id: u32) -> Result<Model> {
        self.get_by_id(id)?
            .ok_or(anyhow::anyhow!("model not found"))
    }

    /// Returns the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn load_model_by_name(&self, name: &str) -> Result<Model> {
        self.indexed_map
            .get_by_key(name.as_bytes())?
            .map(|r| super::deserialize(r.as_ref()))
            .transpose()?
            .ok_or(anyhow::anyhow!("model not found"))
    }

    /// Returns the models between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn load_models(
        &self,
        after: &Option<(u32, String)>,
        before: &Option<(u32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Model>> {
        let (direction, from) = if is_first {
            (
                rocksdb::Direction::Forward,
                after.as_ref().map(|(_id, name)| name.as_bytes()),
            )
        } else {
            (
                rocksdb::Direction::Reverse,
                before.as_ref().map(|(_id, name)| name.as_bytes()),
            )
        };
        let iter = self.iter(direction, from);
        iter.filter_map(|res| {
            res.map(|model| {
                if let Some((id, name)) = after
                    && model.id <= *id
                    && model.name.as_bytes() <= name.as_bytes()
                {
                    return None;
                }
                if let Some((id, name)) = before
                    && model.id >= *id
                    && model.name.as_bytes() >= name.as_bytes()
                {
                    return None;
                }
                Some(model)
            })
            .transpose()
        })
        .take(limit)
        .collect()
    }

    /// Updates the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn update_model(&mut self, model: &Model) -> Result<u32> {
        let old = self.load_model(model.id)?;
        let old = old.into();
        let new = model.into();
        self.update(model.id, &old, &new)?;
        Ok(model.id)
    }
}

impl FromKeyValue for Model {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for Model {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for Model {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }
    fn index(&self) -> u32 {
        self.id
    }
    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }
    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Update {
    name: Option<String>,
    version: Option<i32>,
    kind: Option<String>,
    max_event_id_num: Option<i32>,
    data_source_id: Option<i32>,
    classification_id: Option<i64>,
}

impl From<Model> for Update {
    fn from(model: Model) -> Self {
        Self {
            name: Some(model.name),
            version: Some(model.version),
            kind: Some(model.kind),
            max_event_id_num: Some(model.max_event_id_num),
            data_source_id: Some(model.data_source_id),
            classification_id: model.classification_id,
        }
    }
}

impl From<&Model> for Update {
    fn from(model: &Model) -> Self {
        Self {
            name: Some(model.name.clone()),
            version: Some(model.version),
            kind: Some(model.kind.clone()),
            max_event_id_num: Some(model.max_event_id_num),
            data_source_id: Some(model.data_source_id),
            classification_id: model.classification_id,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = Model;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name
            .as_ref()
            .map(|name| Cow::Borrowed(name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = &self.name {
            value.name.clone_from(name);
        }
        if let Some(version) = self.version {
            value.version = version;
        }
        if let Some(kind) = &self.kind {
            value.kind.clone_from(kind);
        }
        if let Some(max_event_id_num) = self.max_event_id_num {
            value.max_event_id_num = max_event_id_num;
        }
        if let Some(data_source_id) = self.data_source_id {
            value.data_source_id = data_source_id;
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(name) = &self.name
            && name != &value.name
        {
            return false;
        }
        if let Some(version) = self.version
            && version != value.version
        {
            return false;
        }
        if let Some(kind) = &self.kind
            && kind != &value.kind
        {
            return false;
        }
        if let Some(max_event_id_num) = self.max_event_id_num
            && max_event_id_num != value.max_event_id_num
        {
            return false;
        }
        if let Some(data_source_id) = self.data_source_id
            && data_source_id != value.data_source_id
        {
            return false;
        }
        true
    }
}
