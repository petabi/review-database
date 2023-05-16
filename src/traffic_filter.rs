use super::{IterableMap, Store};
use anyhow::{bail, Context, Result};
use bincode::Options;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

type RuleList = Vec<(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)>;

#[derive(Clone, Deserialize, Serialize)]
pub struct TrafficFilter {
    pub agent: String,
    pub rules: HashMap<IpNet, ProtocolPorts>,
    pub last_modification_time: DateTime<Utc>,
    pub update_time: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ProtocolPorts {
    tcp_ports: Option<Vec<u16>>,
    udp_ports: Option<Vec<u16>>,
}

impl ProtocolPorts {
    fn update(&mut self, tcp_ports: Option<Vec<u16>>, udp_ports: Option<Vec<u16>>) {
        self.tcp_ports = tcp_ports;
        if let Some(tcp_ports) = &mut self.tcp_ports {
            tcp_ports.sort_unstable();
            tcp_ports.dedup();
        }

        self.udp_ports = udp_ports;
        if let Some(udp_ports) = &mut self.udp_ports {
            udp_ports.sort_unstable();
            udp_ports.dedup();
        }
    }

    #[must_use]
    pub fn tcp_ports(&self) -> &Option<Vec<u16>> {
        &self.tcp_ports
    }

    #[must_use]
    pub fn udp_ports(&self) -> &Option<Vec<u16>> {
        &self.udp_ports
    }
}

impl TrafficFilter {
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn rules(&self) -> RuleList {
        self.rules
            .iter()
            .map(|(net, ports)| (*net, ports.tcp_ports().clone(), ports.udp_ports().clone()))
            .collect()
    }

    #[must_use]
    pub fn new(
        agent: &str,
        net: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Self {
        let mut rules = HashMap::new();
        rules.insert(
            net,
            ProtocolPorts {
                tcp_ports,
                udp_ports,
            },
        );
        Self {
            agent: agent.to_string(),
            rules,
            last_modification_time: Utc::now(),
            update_time: None,
            description,
        }
    }

    /// Returns filtering rules of agent
    ///
    /// # Errors
    ///
    /// * Return an error if it fails to get rules from database
    /// * Return an error if it fails to decode rules
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

    /// Returns filtering rules of specified or all agents
    ///
    /// # Errors
    ///
    /// * Return an error if it fails to open database
    /// * Return an error if it fails to decode rules
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

    /// Add new rules
    ///
    /// # Errors
    ///
    /// * Returns an error if duplicate rule is already exist in database
    /// * Returns an error if it fails to open database
    /// * Returns an error if it fails to encode rules
    /// * Returns an error if it fails to insert rule in database
    pub fn insert(
        store: &Store,
        agent: &str,
        network: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let tf = match Self::get(store, agent)? {
            Some(mut v) => {
                if let Some(net) = v.check_duplicate(network) {
                    bail!("Duplicate rule found. \"{net}\"");
                }
                v.rules.insert(
                    network,
                    ProtocolPorts {
                        tcp_ports,
                        udp_ports,
                    },
                );
                v.last_modification_time = Utc::now();
                v
            }
            None => Self::new(agent, network, tcp_ports, udp_ports, description),
        };
        let value = bincode::DefaultOptions::new().serialize(&tf)?;
        let map = store.traffic_filter_map();
        map.put(agent.as_bytes(), &value)?;
        Ok(tf.len())
    }

    /// Update ports or description of network
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if agent is not exist in database
    /// * Returns an error if network of agent is not exist in the rules of agent
    /// * Returns an error if it fails to write updated rules in database
    pub fn update(
        store: &Store,
        agent: &str,
        network: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let tf = match Self::get(store, agent)? {
            Some(mut v) => {
                if let Some(ports) = v.rules.get_mut(&network) {
                    ports.update(tcp_ports, udp_ports);
                    if let Some(description) = description {
                        v.description = Some(description);
                    }
                    v.last_modification_time = Utc::now();
                } else {
                    bail!("Rule not found");
                }
                v
            }
            _ => bail!("Agent not found"),
        };
        let value = bincode::DefaultOptions::new().serialize(&tf)?;
        let map = store.traffic_filter_map();
        map.put(agent.as_bytes(), &value)?;
        Ok(tf.len())
    }

    /// Remove some rules. Agent will be removed if rules is empty
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if rule is not exist
    /// * Returns an error if it fails to write updated rules in database
    pub fn remove(store: &Store, agent: &str, networks: &[IpNet]) -> Result<usize> {
        let tf = match Self::get(store, agent)? {
            Some(mut v) => {
                for network in networks {
                    _ = v.rules.remove(network); // ignore when the network doesn't exist
                }
                v.last_modification_time = Utc::now();
                if v.rules.is_empty() {
                    None
                } else {
                    Some(v)
                }
            }
            None => return Ok(0),
        };
        let map = store.traffic_filter_map();
        if let Some(tf) = tf {
            let value = bincode::DefaultOptions::new().serialize(&tf)?;
            map.put(agent.as_bytes(), &value)?;
            Ok(tf.len())
        } else {
            map.delete(agent.as_bytes())?;
            Ok(0)
        }
    }

    /// Update the applied time
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if rule is not exist
    /// * Returns an error if it fails to write updated rules in database
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

    /// Remove all rules of the agent
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to delete agent
    pub fn clear(store: &Store, agent: &str) -> Result<usize> {
        let map = store.traffic_filter_map();
        map.delete(agent.as_bytes())?;
        Ok(0)
    }

    fn check_duplicate(&self, network: IpNet) -> Option<IpNet> {
        if network.addr().is_unspecified() && self.rules.get(&network).is_some() {
            return Some(network);
        }
        self.rules
            .keys()
            .find(|net| {
                if net.addr().is_unspecified() {
                    false
                } else {
                    **net == network || net.contains(&network) || network.contains(*net)
                }
            })
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::IterableMap;
    use crate::{Store, TrafficFilter};
    use std::sync::Arc;

    #[tokio::test]
    async fn insert_get_remove() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let map = store.traffic_filter_map();
        assert!(map.iter_forward().is_ok());
        if let Ok(mut iter) = map.iter_forward() {
            assert!(iter.next().is_none());
        }

        let agent = "piglet@node1";
        let network = "172.30.1.0/24".parse().unwrap();
        let tcp_ports = Some(vec![80, 8000]);
        let udp_ports = None;
        let description = Some("first rule".to_string());

        let r = TrafficFilter::insert(&store, agent, network, tcp_ports, udp_ports, description);
        assert!(r.is_ok());
        if let Ok(len) = r {
            assert_eq!(len, 1);
        }

        let r = TrafficFilter::get(&store, agent);
        assert!(r.is_ok());
        if let Ok(tf) = r {
            assert!(tf.is_some());
            if let Some(tf) = tf {
                assert!(tf.update_time.is_none());
                assert_eq!(&tf.agent, "piglet@node1");
                assert!(tf.rules.contains_key(&network));
            }
        }

        let r = TrafficFilter::get_list(&store, &None);
        assert!(r.is_ok());
        if let Ok(r) = r {
            assert!(r.is_some());
            if let Some(v) = r {
                assert_eq!(v.len(), 1);
            }
        }

        let r = TrafficFilter::remove(&store, "piglet@node1", &vec![network]);
        assert!(r.is_ok());
        if let Ok(len) = r {
            assert_eq!(len, 0);
        }

        let r = TrafficFilter::get_list(&store, &None);
        assert!(r.is_ok());
        if let Ok(r) = r {
            assert!(r.is_none());
        }
    }

    #[tokio::test]
    async fn check_duplicate_update() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        let empty_rules = TrafficFilter::get(&store, "unknown_host");
        assert!(empty_rules.is_ok());
        if let Ok(r) = empty_rules {
            assert!(r.is_none());
        }

        let agent = "node1";
        let any = "0.0.0.0/0".parse().unwrap();
        let r = TrafficFilter::insert(
            &store,
            agent,
            any,
            Some(vec![80, 8000]),
            None,
            Some("any network".to_string()),
        );
        assert!(r.is_ok());

        let r = TrafficFilter::insert(
            &store,
            agent,
            any,
            Some(vec![80]),
            None,
            Some("try duplicate network".to_string()),
        );
        assert!(r.is_err());

        let network = "172.30.0.0/16".parse().unwrap();
        let description = Some("first rule".to_string());
        let r = TrafficFilter::insert(
            &store,
            agent,
            network,
            Some(vec![80, 8000]),
            None,
            description,
        );
        assert!(r.is_ok());

        let new_tcp_ports = vec![8080, 8888];
        let subnet_network = "172.30.1.0/24".parse().unwrap();
        let r = TrafficFilter::insert(
            &store,
            agent,
            subnet_network,
            Some(new_tcp_ports.clone()),
            None,
            None,
        );
        assert!(r.is_err());

        let r = TrafficFilter::update(&store, agent, network, Some(new_tcp_ports), None, None);
        assert!(r.is_ok());

        let r = TrafficFilter::get(&store, agent);
        assert!(r.is_ok());
        if let Ok(Some(tf)) = r {
            if let Some(rule) = tf.rules.get(&network) {
                assert_eq!(rule.tcp_ports, Some(vec![8080, 8888]));
            }
        }
    }
}
