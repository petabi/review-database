use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{tables::Value, UniqueKey};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BatchInfo {
    pub model: i32,
    pub inner: crate::types::ModelBatchInfo,
}

impl BatchInfo {
    #[must_use]
    pub fn new(model: i32, inner: crate::types::ModelBatchInfo) -> Self {
        Self { model, inner }
    }

    #[must_use]
    pub fn into_inner(self) -> crate::types::ModelBatchInfo {
        self.inner
    }
}

impl From<crate::types::ModelBatchInfo> for BatchInfo {
    fn from(inner: crate::types::ModelBatchInfo) -> Self {
        Self {
            model: i32::default(),
            inner,
        }
    }
}

impl UniqueKey for BatchInfo {
    fn unique_key(&self) -> Cow<[u8]> {
        let mut key = self.model.to_be_bytes().to_vec();
        key.extend(self.inner.id.to_be_bytes());

        Cow::Owned(key)
    }
}

impl Value for BatchInfo {
    fn value(&self) -> Cow<[u8]> {
        use bincode::Options;
        let Ok(value) = bincode::DefaultOptions::new().serialize(&self.inner) else {
            unreachable!("serialization into memory should never fail")
        };
        Cow::Owned(value)
    }
}
