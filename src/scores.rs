use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::tables::{Key, Value};

#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct Scores {
    pub model: i32,
    inner: crate::types::ModelScores,
}

impl Scores {
    pub fn new(model: i32, inner: crate::types::ModelScores) -> Self {
        Self { model, inner }
    }

    pub fn into_inner(self) -> crate::types::ModelScores {
        self.inner
    }
}

impl Key for Scores {
    fn key(&self) -> Cow<[u8]> {
        use bincode::Options;
        let Ok(key) = bincode::DefaultOptions::new().serialize(&self.model) else {
            unreachable!("serialization into memory should never fail")
        };
        Cow::Owned(key)
    }
}

impl Value for Scores {
    fn value(&self) -> Cow<[u8]> {
        use bincode::Options;
        let Ok(value) = bincode::DefaultOptions::new().serialize(&self.inner) else {
            unreachable!("serialization into memory should never fail")
        };
        Cow::Owned(value)
    }
}
