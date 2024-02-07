use super::ArchiveBackupInfo;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_POSTGRES_DUMP_FILE: &str = "postgres.dump";
const DEFAULT_TEMP_DIR: &str = "/tmp";
pub(super) const DEFAULT_ZIP_EXTENSION: &str = "bck";

#[derive(Clone, Debug)]
pub struct BackupConfig {
    pub backup_path: PathBuf,
    pub postgres_db_path: String,
    pub postgres_db_dirname: String,
    pub container: String,
    pub host: String,
    pub port: String,
    pub user: String,
    pub name: String,
    pub env_path: String, // Environment variable values for running command
}

impl BackupConfig {
    #[must_use]
    pub fn builder() -> BackupConfigBuilder {
        BackupConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct BackupConfigBuilder {
    backup_path: PathBuf,
    postgres_db_path: String,
    postgres_db_dirname: String,
    container: String,
    host: String,
    port: String,
    user: String,
    name: String,
    env_path: String,
    review_data_path: String,
}

impl BackupConfigBuilder {
    pub fn backup_path(mut self, backup_path: &Path) -> Self {
        self.backup_path = backup_path.to_path_buf();
        self
    }

    pub fn container(mut self, container: &str) -> Self {
        self.container = container.to_string();
        self
    }

    pub fn database_dir(mut self, postgres_path: &Path) -> Result<Self> {
        let Some(postgres_db_path) = postgres_path.to_str() else {
            return Err(anyhow!("Failed to parse database dir path"));
        };
        self.postgres_db_path = postgres_db_path.to_string();
        let split_path = postgres_db_path.split('/').collect::<Vec<&str>>();
        let Some(postgres_db_dirname) = split_path.last() else {
            return Err(anyhow!("Failed to parse database dir name"));
        };
        self.postgres_db_dirname = (*postgres_db_dirname).to_string();
        Ok(self)
    }

    pub fn database_url(mut self, database_url: &str) -> Result<Self> {
        let Ok(reg) = Regex::new(r"postgres://(\w+):(\w+)@([\w\.-]+):(\d+)/(\w+)") else {
            return Err(anyhow!("Failed to generate Regex"));
        };
        let Some(caps) = reg.captures(database_url) else {
            return Err(anyhow!("Failed to capture url"));
        };
        self.user = caps[1].to_string();
        self.host = caps[3].to_string();
        self.port = caps[4].to_string();
        self.name = caps[5].to_string();
        Ok(self)
    }

    pub fn env_path(mut self, paths: &str) -> Self {
        self.env_path = paths.to_string();
        self
    }

    pub fn review_data_path(mut self, review_data_path: &str) -> Self {
        self.review_data_path = review_data_path.to_string();
        self
    }

    pub fn build(self) -> BackupConfig {
        BackupConfig {
            backup_path: self.backup_path,
            postgres_db_path: self.postgres_db_path,
            postgres_db_dirname: self.postgres_db_dirname,
            container: self.container,
            host: self.host,
            port: self.port,
            user: self.user,
            name: self.name,
            env_path: self.env_path,
        }
    }
}

/// Backup postgres database
///
/// # Errors
///
/// * dump command not found
/// * fail to dump
pub(super) fn create_postgres_backup(cfg: &BackupConfig, temp_backup_path: &str) -> Result<()> {
    // check database path
    if !Path::new(&cfg.postgres_db_path).exists() {
        return Err(anyhow!("No database found"));
    }

    // backup postgres db
    let dump = format!("{temp_backup_path}/{DEFAULT_POSTGRES_DUMP_FILE}");

    // dump docker's postgres db
    postgres_dump_docker(cfg, &dump)?;

    Ok(())
}

/// # Errors
/// * dump command not found
/// * fail to dump
fn postgres_dump_docker(cfg: &BackupConfig, to: &str) -> Result<()> {
    let dump_file_in_docker = format!("{DEFAULT_TEMP_DIR}/{DEFAULT_POSTGRES_DUMP_FILE}");
    let args = vec![
        "exec",
        "-i",
        &cfg.container,
        "/bin/rm",
        "-f",
        &dump_file_in_docker,
    ];

    run_command("docker", &cfg.env_path, &args)
        .with_context(|| anyhow!("failed to remove old dump file"))?;

    let args = vec![
        "exec",
        "-i",
        &cfg.container,
        "pg_dump",
        "-w",
        "-h",
        &cfg.host,
        "-p",
        &cfg.port,
        "-U",
        &cfg.user,
        "-d",
        &cfg.name,
        "-Fc",
        "-f",
        &dump_file_in_docker,
    ];
    run_command("docker", &cfg.env_path, &args)
        .with_context(|| anyhow!("failed to make backup for relational database"))?;

    let from = format!("{}:{dump_file_in_docker}", &cfg.container);
    run_command("docker", &cfg.env_path, &["cp", &from, to])
        .with_context(|| anyhow!("failed to copy dump file"))?;

    Ok(())
}

/// # Errors
/// * get error code from executed command
pub fn run_command(cmd: &str, env_path: &str, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new(cmd);
    cmd.env("PATH", env_path);
    for arg in args {
        if !arg.is_empty() {
            cmd.arg(arg);
        }
    }

    let child = cmd
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()?;

    match child.wait_with_output() {
        Ok(status) => {
            let output_err = String::from_utf8_lossy(&status.stderr);
            if !output_err.is_empty() {
                return Err(anyhow!("{output_err}"));
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("{}", e)),
    }
}

/// # Errors
/// * fail to read path & metadata
pub(super) fn backup_list(dir: &Path) -> Result<Vec<ArchiveBackupInfo>> {
    let mut backup_info: Vec<ArchiveBackupInfo> = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == DEFAULT_ZIP_EXTENSION {
                        let metadata = fs::metadata(&path)?;
                        let file_size = metadata.len();
                        let creation_time = DateTime::<Utc>::from(metadata.created()?);
                        if let Some(file_name) = path.file_name() {
                            if let Some(file_name) = file_name.to_str() {
                                backup_info.push(ArchiveBackupInfo {
                                    file_name: file_name.to_string(),
                                    file_size,
                                    creation_time,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(backup_info)
}

/// # Errors
/// * fail to read path & metadata
pub(super) fn backup_list_len(dir: &Path) -> usize {
    let mut count: usize = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == DEFAULT_ZIP_EXTENSION {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}
