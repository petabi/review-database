use super::{Database, Error, IterableMap, Store, Type};
use anyhow::{bail, Context, Result};
use bincode::Options;
use data_encoding::BASE64;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read};

#[derive(Clone, Deserialize, Serialize)]
pub struct Tidb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: TidbKind,
    pub version: String,
    pub patterns: Vec<TidbRule>,
}

impl Tidb {
    /// Parse and validate input TI database
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to decode or uncompress input TI database
    /// * Returns an error if the input TI database is invalid
    pub fn new(data: &str) -> Result<Self> {
        let data = BASE64.decode(data.as_bytes())?;
        let decoder = GzDecoder::new(&data[..]);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(decoder);
        reader.read_to_end(&mut buf)?;
        let tidb: Tidb = bincode::deserialize(&buf).context("invalid value in database")?;
        tidb.validate()?;
        Ok(tidb)
    }

    fn validate(&self) -> Result<()> {
        if self.id == 0 {
            bail!("invalid db id");
        } else if self.name.trim().is_empty() {
            bail!("invalid db name");
        } else if self.version.trim().is_empty() {
            bail!("db version is required");
        }
        Ok(())
    }

    /// Insert new TI database
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to encode TI database
    /// * Returns an error if it fails to save TI database
    pub fn insert(&self, store: &Store) -> Result<(String, String)> {
        let name = self.name.clone();
        let version = self.version.clone();
        let value = bincode::DefaultOptions::new().serialize(&self)?;
        let map = store.tidb_map();
        map.put(name.as_bytes(), &value)?;
        Ok((name, version))
    }

    /// Replace TI database with the new
    ///
    /// # Errors
    ///
    /// * Returns an error if the TI database name does not match
    /// * Returns an error if it fails to encode TI database
    /// * Returns an error if it fails to delete or save TI database
    pub fn update(&self, store: &Store, name: &str) -> Result<(String, String)> {
        if *name != self.name {
            bail!("Tidb name does not matched");
        }
        let new_name = self.name.clone();
        let new_version = self.version.clone();
        let value = bincode::DefaultOptions::new().serialize(&self)?;
        let map = store.tidb_map();
        map.delete(name.as_bytes())?;
        map.put(name.as_bytes(), &value)?;
        Ok((new_name, new_version))
    }

    /// Returns TI database
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to read database
    /// * Returns an error if it fails to decode TI database
    /// * Returns an error if the TI database does not exist
    pub fn get(store: &Store, name: &str) -> Result<Tidb> {
        let map = store.tidb_map();
        let tidb = match map.get(name.as_bytes())? {
            Some(v) => bincode::DefaultOptions::new()
                .deserialize::<Tidb>(v.as_ref())
                .context("invalid value in database")?,
            None => bail!("no such tidb"),
        };
        Ok(tidb)
    }

    /// Returns the list of TI databases
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to read database
    /// * Returns an error if it fails to decode TI database
    /// * Returns an error if the rule does not exist
    pub fn get_list(store: &Store) -> Result<Vec<Tidb>> {
        let mut tidb_list = Vec::new();
        let map = store.tidb_map();
        for (_, value) in map.iter_forward()? {
            let tidb = bincode::DefaultOptions::new()
                .deserialize::<Tidb>(value.as_ref())
                .context("invalid tidb data")?;
            tidb_list.push(tidb);
        }
        tidb_list.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok(tidb_list)
    }

    /// Returns TI database name and database for the specified name and version
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to decode TI database
    pub fn get_patterns(
        store: &Store,
        dbnames: Vec<(String, String)>,
    ) -> Result<Vec<(String, Option<Tidb>)>> {
        let tidb_map = store.tidb_map();

        //TODO: This job is too heavy if tidb is nothing changed.
        //      Tidb header and patterns should be stored separately.
        let mut ret = Vec::new();
        for (db_name, db_version) in dbnames {
            let Some(value) = tidb_map.get(db_name.as_bytes())? else {
              return Ok(Vec::new())
            };

            let tidb = bincode::DefaultOptions::new()
                .deserialize::<Tidb>(value.as_ref())
                .context("invalid tidb data")?;

            //TODO: These conf should be from the Model's Template
            if tidb.version == db_version {
                ret.push((db_name, None));
            } else {
                let patterns = tidb
                    .patterns
                    .into_iter()
                    .filter_map(|rule| {
                        rule.signatures.map(|sigs| TidbRule {
                            rule_id: rule.rule_id,
                            name: rule.name,
                            description: None,
                            references: None,
                            samples: None,
                            signatures: Some(sigs),
                        })
                    })
                    .collect();
                ret.push((
                    db_name,
                    Some(Tidb {
                        id: tidb.id,
                        name: tidb.name,
                        description: tidb.description,
                        kind: tidb.kind,
                        version: tidb.version,
                        patterns,
                    }),
                ));
            }
        }
        Ok(ret)
    }

    /// Returns rule
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to get rule for the specified name
    /// * Returns an error if it fails to decode TI database
    /// * Returns an error if the TI database does not exist
    pub fn get_rule(store: &Store, name: &str, rule_id: u32) -> Result<Option<TidbRule>> {
        let map = store.tidb_map();
        let tidb = match map.get(name.as_bytes())? {
            Some(v) => bincode::DefaultOptions::new()
                .deserialize::<Tidb>(v.as_ref())
                .context("invalid value in database")?,
            None => bail!("no such tidb"),
        };

        tidb.patterns
            .iter()
            .find(|rule| rule.rule_id == rule_id)
            .map_or(Ok(None), |rule| Ok(Some(rule.clone())))
    }

    /// Removes TI database
    ///
    /// # Errors
    ///
    /// * Returns an error if it failes to remove value from database
    pub fn remove(store: &Store, name: &str) -> Result<()> {
        let map = store.tidb_map();
        map.delete(name.as_bytes())?;
        Ok(())
    }

    #[must_use]
    pub fn patterns(&self) -> String {
        format!("{} rules", self.patterns.len())
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TidbRule {
    pub rule_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TidbKind {
    Ip,
    Url,
    Token,
    Regex,
}

impl Database {
    pub async fn update_agent_status(&self, hostname: String, status: bool) -> Result<(), Error> {
        let conn = self.pool.get().await?;
        let id = conn
            .select_one_from::<i32>("node", &["id"], &[("hostname", Type::TEXT)], &[&hostname])
            .await?;
        conn.update("node", id, &[("status", Type::BOOL)], &[&status])
            .await?;
        Ok(())
    }
}
