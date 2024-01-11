use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{Indexable, IndexedMapUpdate};

/// A category for a cluster.
#[derive(Debug, Deserialize, Queryable, Serialize, PartialEq, Eq)]
pub struct Category {
    pub id: u32,
    pub name: String,
}

impl PartialOrd for Category {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Category {
    fn cmp(&self, other: &Self) -> Ordering {
        let ord = self.name.cmp(&other.name);
        match ord {
            Ordering::Equal => self.id.cmp(&other.id),
            _ => ord,
        }
    }
}

impl Indexable for Category {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn value(&self) -> Vec<u8> {
        use bincode::Options;

        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

impl IndexedMapUpdate for Category {
    type Entry = Category;

    fn key(&self) -> Option<&[u8]> {
        if self.name.is_empty() {
            None
        } else {
            Some(self.name.as_bytes())
        }
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.name == value.name
    }
}
