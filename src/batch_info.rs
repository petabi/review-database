use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct BatchInfo {
    model: i32,
    id: i64,
    earliest: i64,
    latest: i64,
    sources: Vec<String>,
}

impl BatchInfo {
    pub(crate) fn key(&self) -> (i32, i64) {
        (self.model, self.id)
    }

    pub(crate) fn value(&self) -> (i64, i64, &[String]) {
        (self.earliest, self.latest, &self.sources)
    }
}
