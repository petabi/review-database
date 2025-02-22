use serde::{Deserialize, Serialize};

use crate::{UniqueKey, tables::Value};

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
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn unique_key(&self) -> Self::AsBytes<'_> {
        let mut key = self.model.to_be_bytes().to_vec();
        key.extend(self.inner.id.to_be_bytes());
        key
    }
}

impl Value for BatchInfo {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        use bincode::Options;
        let Ok(value) = bincode::DefaultOptions::new().serialize(&self.inner) else {
            unreachable!("serialization into memory should never fail")
        };
        value
    }
}
