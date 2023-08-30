use serde::{Deserialize, Serialize};

use crate::tables::{Key, Value};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BatchInfo {
    model: i32,
    inner: crate::types::ModelBatchInfo,
}

impl BatchInfo {
    pub fn new(model: i32, inner: crate::types::ModelBatchInfo) -> Self {
        Self { model, inner }
    }

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

impl Key for BatchInfo {
    type Output<'a> = (i32, i64);

    fn key(&self) -> Self::Output<'_> {
        (self.model, self.inner.id)
    }
}

impl Value for BatchInfo {
    type Output<'a> = (i64, i64, &'a [String]);

    fn value(&self) -> Self::Output<'_> {
        (self.inner.earliest, self.inner.latest, &self.inner.sources)
    }
}
