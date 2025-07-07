use std::{
    env,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context, Result};
use config::File;
use review_database::{Database, Store, migrate_backend, migrate_data_dir};
use serde::Deserialize;

#[cfg(feature = "migrate")]
#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load_config(parse().as_deref())?;
    migrate_data_dir(&config.data_dir, &config.backup_dir).context("migration failed")?;

    let db = Database::new(&config.database_url, &config.ca_certs(), &config.data_dir)
        .await
        .context("failed to connect to the PostgreSQL database")?;
    let store = Store::new(&config.data_dir, &config.backup_dir)?;

    // transfer data from PostgreSQL to RocksDB.
    migrate_backend(&db, &store, &config.data_dir).await?;
    Ok(())
}

fn parse() -> Option<String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        return None;
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{} {}", bin(), version());
        println!();
        println!(
            "USAGE: \
            \n    {} [CONFIG] \
            \n \
            \nFLAGS: \
            \n    -h, --help       Prints help information \
            \n    -V, --version    Prints version information \
            \n \
            \nARG: \
            \n    <CONFIG>    A TOML config file",
            bin()
        );
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }

    Some(args[1].clone())
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn bin() -> &'static str {
    env!("CARGO_BIN_NAME")
}

pub struct Config {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    database_url: String,
    ca_certs: Vec<PathBuf>,
}

impl Config {
    const DEFAULT_DATABASE_URL: &'static str = "postgres://review@localhost/review";
    /// Reads configuration from the file on disk and environment variables and
    /// returns Config struct.
    ///
    /// # Errors
    ///
    /// If input arguments are invalid, an error will be returned.
    pub fn load_config(path: Option<&str>) -> Result<Self> {
        let builder = config::Config::builder()
            .set_default("database_url", Self::DEFAULT_DATABASE_URL)
            .context("cannot set the default database URL")?
            .set_default("data_dir", env::current_dir()?.join("data").to_str())
            .context("cannot set the default data directory")?
            .set_default("backup_dir", env::current_dir()?.join("backup").to_str())
            .context("cannot set the default backup directory")?;
        let config: ConfigParser = if let Some(path) = path {
            builder.add_source(File::with_name(path))
        } else {
            builder
        }
        .build()
        .context("cannot build the config")?
        .try_deserialize()?;
        Ok(Self {
            data_dir: config.data_dir,
            backup_dir: config.backup_dir,
            database_url: config.database_url,
            ca_certs: config.ca_certs.unwrap_or_default(),
        })
    }

    #[must_use]
    fn ca_certs(&self) -> Vec<&Path> {
        self.ca_certs
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct ConfigParser {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    database_url: String,
    ca_certs: Option<Vec<PathBuf>>,
}
