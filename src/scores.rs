use serde::{Deserialize, Serialize};

use crate::tables::{Key, Value};

#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct Scores {
    model: i32,
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
    type Output<'a> = &'a i32;

    fn key(&self) -> Self::Output<'_> {
        &self.model
    }
}

impl Value for Scores {
    type Output<'a> = &'a crate::types::ModelScores;

    fn value(&self) -> Self::Output<'_> {
        &self.inner
    }
}
