//! The `TriagePolicy` table.

use std::{borrow::Cow, cmp::Ordering};

use anyhow::Result;
use attrievent::attribute::RawEventKind;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable,
    collections::Indexed,
    types::{EventCategory, FromKeyValue},
};

#[derive(Clone, Deserialize, Serialize)]
pub struct TriagePolicy {
    pub id: u32,
    pub name: String,
    pub ti_db: Vec<Ti>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for TriagePolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TriagePolicy {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for TriagePolicy {
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

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum TiCmpKind {
    IpAddress,
    Domain,
    Hostname,
    Uri,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ValueKind {
    String,
    Integer,  // range: i64::MAX
    UInteger, // range: u64::MAX
    Vector,
    Float,
    IpAddr,
    Bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum AttrCmpKind {
    Less,
    Equal,
    Greater,
    LessOrEqual,
    GreaterOrEqual,
    Contain,
    OpenRange,
    CloseRange,
    LeftOpenRange,
    RightOpenRange,
    NotEqual,
    NotContain,
    NotOpenRange,
    NotCloseRange,
    NotLeftOpenRange,
    NotRightOpenRange,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ResponseKind {
    Manual,
    Blacklist,
    Whitelist,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Ti {
    pub ti_name: String,
    pub kind: TiCmpKind,
    pub weight: Option<f64>,
}

impl Eq for Ti {}

impl PartialOrd for Ti {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ti {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.ti_name.cmp(&other.ti_name);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.kind.cmp(&other.kind);
        if second != Ordering::Equal {
            return second;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct PacketAttr {
    pub raw_event_kind: RawEventKind,
    pub attr_name: String,
    pub value_kind: ValueKind,
    pub cmp_kind: AttrCmpKind,
    pub first_value: Vec<u8>,
    pub second_value: Option<Vec<u8>>,
    pub weight: Option<f64>,
}

impl Eq for PacketAttr {}

impl PartialOrd for PacketAttr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketAttr {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.attr_name.cmp(&other.attr_name);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.value_kind.cmp(&other.value_kind);
        if second != Ordering::Equal {
            return second;
        }
        let third = self.cmp_kind.cmp(&other.cmp_kind);
        if third != Ordering::Equal {
            return third;
        }
        let fourth = self.first_value.cmp(&other.first_value);
        if fourth != Ordering::Equal {
            return fourth;
        }
        let fifth = self.second_value.cmp(&other.second_value);
        if fifth != Ordering::Equal {
            return fifth;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Confidence {
    pub threat_category: EventCategory,
    pub threat_kind: String,
    pub confidence: f64,
    pub weight: Option<f64>,
}

impl Eq for Confidence {}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.threat_category.cmp(&other.threat_category);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.threat_kind.cmp(&other.threat_kind);
        if second != Ordering::Equal {
            return second;
        }
        let third = self.confidence.total_cmp(&other.confidence);
        if third != Ordering::Equal {
            return third;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Response {
    pub minimum_score: f64,
    pub kind: ResponseKind,
}

impl Eq for Response {}

impl PartialOrd for Response {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Response {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.minimum_score.total_cmp(&other.minimum_score);
        if first != Ordering::Equal {
            return first;
        }
        self.kind.cmp(&other.kind)
    }
}

/// Functions for the `triage_policy` indexed map.
impl<'d> IndexedTable<'d, TriagePolicy> {
    /// Opens the `triage_policy` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::TRIAGE_POLICY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `TriagePolicy` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: String,
    pub ti_db: Vec<Ti>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
}

impl IndexedMapUpdate for Update {
    type Entry = TriagePolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        let mut ti_db = self.ti_db.clone();
        ti_db.sort_unstable();
        value.ti_db = ti_db;

        let mut packet_attr: Vec<PacketAttr> = self.packet_attr.clone();
        packet_attr.sort_unstable();
        value.packet_attr = packet_attr;

        let mut confidence = self.confidence.clone();
        confidence.sort_unstable();
        value.confidence = confidence;

        let mut response = self.response.clone();
        response.sort_unstable();
        value.response = response;

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        let mut ti_db = self.ti_db.clone();
        ti_db.sort_unstable();
        if ti_db != value.ti_db {
            return false;
        }
        let mut packet_attr = self.packet_attr.clone();
        packet_attr.sort_unstable();
        if packet_attr != value.packet_attr {
            return false;
        }

        let mut confidence = self.confidence.clone();
        confidence.sort_unstable();
        if confidence != value.confidence {
            return false;
        }

        let mut response = self.response.clone();
        response.sort_unstable();
        if response != value.response {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use chrono::Utc;

    use crate::{Store, TriagePolicy, TriagePolicyUpdate};

    #[test]
    fn update() {
        let store = setup_store();
        let mut table = store.triage_policy_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let old = create_update("a");

        let update = create_update("b");

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_entry(name: &str) -> TriagePolicy {
        TriagePolicy {
            id: u32::MAX,
            name: name.to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            response: vec![],
            confidence: vec![],
            creation_time: Utc::now(),
        }
    }

    fn create_update(name: &str) -> TriagePolicyUpdate {
        TriagePolicyUpdate {
            name: name.to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            confidence: vec![],
            response: vec![],
        }
    }
}
