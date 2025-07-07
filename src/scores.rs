use serde::{Deserialize, Serialize};

use crate::{UniqueKey, tables::Value};

#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct Scores {
    pub model: i32,
    inner: crate::types::ModelScores,
}

impl Scores {
    #[must_use]
    pub fn new(model: i32, inner: crate::types::ModelScores) -> Self {
        Self { model, inner }
    }

    #[must_use]
    pub fn into_inner(self) -> crate::types::ModelScores {
        self.inner
    }
}

impl UniqueKey for Scores {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        use bincode::Options;
        let Ok(key) = bincode::DefaultOptions::new().serialize(&self.model) else {
            unreachable!("serialization into memory should never fail")
        };
        key
    }
}

impl Value for Scores {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        use bincode::Options;
        let Ok(value) = bincode::DefaultOptions::new().serialize(&self.inner) else {
            unreachable!("serialization into memory should never fail")
        };
        value
    }
}
