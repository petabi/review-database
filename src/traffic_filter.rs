use super::{IterableMap, Store};
use anyhow::{bail, Context, Result};
use bincode::Options;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Deserialize, Serialize)]
pub struct TrafficFilter {
    pub agent: String,
    pub rules: Vec<IpNet>,
    pub last_modification_time: DateTime<Utc>,
    pub update_time: Option<DateTime<Utc>>,
}

impl TrafficFilter {
    #[must_use]
    pub fn rules(&self) -> &Vec<IpNet> {
        &self.rules
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn new(agent: &str, data: &[String]) -> Result<Self> {
        let mut rules = Vec::new();
        let mut errors = Vec::new();
        for rule in data {
            if let Ok(n) = IpNet::from_str(rule) {
                rules.push(n);
            } else {
                errors.push(rule.as_str());
            }
        }
        if !errors.is_empty() {
            bail!("invalid traffic filter rules. {:?}", errors)
        }
        Ok(Self {
            agent: agent.to_string(),
            rules,
            last_modification_time: Utc::now(),
            update_time: None,
        })
    }

    /// returns filtering rules
    pub fn get(store: &Store, agent: &str) -> Result<Option<TrafficFilter>> {
        let map = store.traffic_filter_map();
        match map.get(agent.as_bytes())? {
            Some(v) => Ok(Some(
                bincode::DefaultOptions::new()
                    .deserialize::<TrafficFilter>(v.as_ref())
                    .context("invalid value in database")?,
            )),
            None => Ok(None),
        }
    }

    // returns filtering rules of all agents
    pub fn get_list(
        store: &Store,
        agents: &Option<Vec<String>>,
    ) -> Result<Option<Vec<TrafficFilter>>> {
        let map = store.traffic_filter_map();
        let mut res = Vec::new();
        for (key, value) in map.iter_forward()? {
            let agent = String::from_utf8_lossy(&key).to_string();
            let included = if let Some(agents) = agents {
                agents.contains(&agent)
            } else {
                true
            };
            if included {
                res.push(
                    bincode::DefaultOptions::new()
                        .deserialize::<TrafficFilter>(value.as_ref())
                        .context("invalid value in database")?,
                );
            }
        }
        if res.is_empty() {
            Ok(None)
        } else {
            Ok(Some(res))
        }
    }

    /// adds new rules
    pub fn insert(store: &Store, agent: &str, rules: &[String]) -> Result<usize> {
        let tf = match Self::get(store, agent)? {
            Some(mut v) => {
                v.merge(rules, true)?;
                v.last_modification_time = Utc::now();
                v
            }
            None => Self::new(agent, rules)?,
        };
        let value = bincode::DefaultOptions::new().serialize(&tf)?;
        let map = store.traffic_filter_map();
        map.put(agent.as_bytes(), &value)?;
        Ok(tf.len())
    }

    /// replaces existing rules with new rules
    pub fn replace(&self, store: &Store) -> Result<()> {
        let value = bincode::DefaultOptions::new().serialize(&self)?;
        let map = store.traffic_filter_map();
        map.put(self.agent.as_bytes(), &value)?;
        Ok(())
    }

    /// remove some rules
    pub fn remove(store: &Store, agent: &str, rules: &[String]) -> Result<usize> {
        let tf = match Self::get(store, agent)? {
            Some(mut v) => {
                v.merge(rules, false)?;
                v.last_modification_time = Utc::now();
                v
            }
            None => return Ok(0),
        };

        let value = bincode::DefaultOptions::new().serialize(&tf)?;
        let map = store.traffic_filter_map();
        map.put(agent.as_bytes(), &value)?;
        Ok(tf.len())
    }

    /// update the applied time
    pub fn update_time(store: &Store, agent: &str) -> Result<()> {
        let map = store.traffic_filter_map();
        if let Some(tf) = map.get(agent.as_bytes())? {
            let mut tf = bincode::DefaultOptions::new()
                .deserialize::<TrafficFilter>(tf.as_ref())
                .context("invalid value in database")?;
            tf.update_time = Some(Utc::now());
            let value = bincode::DefaultOptions::new().serialize(&tf)?;
            map.put(agent.as_bytes(), &value)?;
        }
        Ok(())
    }

    /// remove all rules of the agent
    pub fn clear(store: &Store, agent: &str) -> Result<usize> {
        let map = store.traffic_filter_map();
        map.delete(agent.as_bytes())?;
        Ok(0)
    }

    fn merge(&mut self, rules: &[String], plus: bool) -> Result<()> {
        let new_rules = rules
            .iter()
            .filter_map(|rule| IpNet::from_str(rule).ok())
            .collect::<Vec<_>>();
        if plus {
            if rules.len() != new_rules.len() {
                bail!("invalid traffic filter rules");
            }
            self.rules.extend(new_rules);
            self.rules.sort();
            self.rules.dedup();
        } else {
            self.rules.retain(|rule| !new_rules.contains(rule));
        }
        Ok(())
    }
}
