use super::BackupInfo;
use anyhow::{anyhow, Context, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::tempdir_in;

const DEFAULT_POSTGRES_DB: &str = "database.db";
const DEFAULT_POSTGRES_DUMP_FILE: &str = "postgres.dump";
const DEFAULT_TEMP_DIR: &str = "/tmp";
const DEFAULT_ZIP_DIR: &str = "data";

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
    pub num_of_backups: u32,
    pub env_path: String, // Environment variable values for running command
    pub review_data_path: String, // Path to the root folder containing review-related data
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
    num_of_backups: u32,
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

    pub fn num_of_backup(mut self, num_of_backups: u32) -> Self {
        self.num_of_backups = num_of_backups;
        self
    }

    pub fn database_dir(mut self, postgres_path: &Path) -> Result<Self> {
        let Some(postgres_db_path) = postgres_path.to_str() else {
            return Err(anyhow!("Failed to parse databse dir path"));
        };
        self.postgres_db_path = postgres_db_path.to_string();
        let split_path = postgres_db_path.split('/').collect::<Vec<&str>>();
        let Some(postgres_db_dirname) = split_path.last() else{
            return Err(anyhow!("Failed to parse databse dir name"));
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
            num_of_backups: self.num_of_backups,
            env_path: self.env_path,
            review_data_path: self.review_data_path,
        }
    }
}

/// Restore postgres database from the backup with `backup_id` on file
///
/// # Errors
///
/// Returns an error when postgres's restoration fails.
pub(super) fn postgres_restore(cfg: &BackupConfig, backup_id: u32) -> Result<()> {
    let file_name = format!("{backup_id}.bck");
    let restore_path = cfg.backup_path.join(DEFAULT_POSTGRES_DB).join(file_name);
    if !restore_path.exists() {
        return Err(anyhow!("backup file not found"));
    }
    if !Path::new(&cfg.postgres_db_path).exists() {
        return Err(anyhow!("Running database not found!"));
    }
    restore_data(cfg, &restore_path)?;
    Ok(())
}

/// Return the integrated backup information by adding the postgres backup
/// information to the backup information in rocksdb where the `backup_id` matches.
///
/// # Errors
///
/// Returns an error when postgres fails to create a list.
pub(super) fn postgres_backup_list(
    backup_path: &Path,
    backup_list: &mut [BackupInfo],
) -> Result<()> {
    let data_backup_path = format!("{}/{}", backup_path.to_string_lossy(), DEFAULT_POSTGRES_DB);
    detail_files(&data_backup_path, backup_list)?;
    Ok(())
}

/// Backup postgres database and purge the backup by referring the backup
/// list maintained by rocksdb.
///
/// # Errors
///
/// Returns an error when postgres's backup fails.
pub(super) fn postgres_backup(cfg: &BackupConfig, backup_id_list: Vec<u32>) -> Result<()> {
    let Some(new_backup_id) = backup_id_list.last() else {
        return Err(anyhow!("backup is not exist"));
    };

    //create backup
    let data_backup_path = create_postgres_backup(cfg, *new_backup_id)?;

    //purge old backups
    purge_old_postgres_backups(&data_backup_path, backup_id_list)?;
    Ok(())
}

/// purge the backup by referring the backup list maintained by rocksdb.
///
/// # Errors
///
/// Returns an error when postgres's purge fails.
pub(super) fn purge_old_postgres_backups(
    data_backup_path: &str,
    backup_id_list: Vec<u32>,
) -> Result<()> {
    let files = fs::read_dir(Path::new(&data_backup_path))?;

    let file_list: HashSet<String> = files
        .into_iter()
        .filter_map(|file| {
            file.ok().and_then(|dir_entry| {
                let file_name = dir_entry.file_name();
                file_name.to_str().map(std::string::ToString::to_string)
            })
        })
        .collect();

    let backuped_id_list: HashSet<String> = backup_id_list
        .into_iter()
        .map(|id| format!("{id}.bck"))
        .collect();

    let diff_list = file_list.difference(&backuped_id_list);
    for diff in diff_list {
        let file_path = format!("/{data_backup_path}/{diff}");
        fs::remove_file(&file_path)?;
    }
    Ok(())
}

/// # Errors
/// * dump command not found
/// * fail to dump
fn create_postgres_backup(cfg: &BackupConfig, new_backup_id: u32) -> Result<String> {
    // check database path
    if !Path::new(&cfg.postgres_db_path).exists() {
        return Err(anyhow!("No database found"));
    }

    //create backup folder
    let Ok(data_backup_path) = create_backup_path(cfg) else {
        return Err(anyhow!("Backup folder creation failed"));
    };

    // mkdir temporary folder (specify a path that can cover a large capacity)
    let temp_dir = tempdir_in(&cfg.review_data_path)?;
    let Some(temp_dir_path) = temp_dir.path().to_str() else {
        return Err(anyhow!("Backup temporary folder creation failed"));
    };
    let tmpdir = format!("{temp_dir_path}/{new_backup_id}");
    if fs::create_dir(&tmpdir).is_err() {
        return Err(anyhow!("Backup temporary folder creation failed"));
    }

    // backup postgres db
    let dump = format!("{tmpdir}/{DEFAULT_POSTGRES_DUMP_FILE}");

    // dump docker's postgres db
    postgres_dump_docker(cfg, &dump)?;

    // make new backup zip file
    let zip_path = format!("/{data_backup_path}/{new_backup_id}.bck");
    tar_gz(&tmpdir, &zip_path)?;

    Ok(data_backup_path)
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
/// * restore command not found
/// * fail to restore
fn postgres_restore_docker(cfg: &BackupConfig, dump: &str, old_db_temp: &str) -> Result<()> {
    // copy current database folder (For manual restore)
    if let Err(e) = run_command(
        "cp",
        &cfg.env_path,
        &["-r", &cfg.postgres_db_path, old_db_temp],
    ) {
        return Err(anyhow!("fail to copy old database. {:?}", e));
    }

    // copy backup file into postgres docker container
    let dump_in_docker = format!("{DEFAULT_TEMP_DIR}/{DEFAULT_POSTGRES_DUMP_FILE}");
    let to = format!("{}:{dump_in_docker}", cfg.container);
    run_command("docker", &cfg.env_path, &["cp", dump, &to])?;

    // restore dump file
    let args = vec![
        "exec",
        "-i",
        &cfg.container,
        "pg_restore",
        "-c",
        "-h",
        &cfg.host,
        "-p",
        &cfg.port,
        "-U",
        &cfg.user,
        "-d",
        &cfg.name,
        &dump_in_docker,
    ];
    run_command("docker", &cfg.env_path, &args)?;
    Ok(())
}

/// remove temporary files.
///
/// # Errors
/// * failed to remove dir/files
fn remove_tmpdir_all(path: &str) -> Result<()> {
    if fs::remove_dir_all(path).is_err() {
        return Err(anyhow!("Backup temporary folder deletion failed"));
    }
    Ok(())
}

/// # Errors
/// * failed to create backup directory
pub(super) fn create_backup_path(cfg: &BackupConfig) -> Result<String> {
    let data_backup_path = format!(
        "{}/{}",
        cfg.backup_path.to_string_lossy(),
        DEFAULT_POSTGRES_DB
    );
    if !Path::new(&data_backup_path).exists() {
        fs::create_dir(&data_backup_path)?;
    }
    Ok(data_backup_path)
}

/// # Errors
/// * get error code from executed command
fn run_command(cmd: &str, env_path: &str, args: &[&str]) -> Result<()> {
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

/// tar and gzip files
/// # Errors
/// * fail to create backup file in backup path
/// * fail to save the files in tmp foler into backup file
/// * fail to finish for the tar and gzipped backup file
fn tar_gz(from: &str, to: &str) -> Result<(), anyhow::Error> {
    let tgz = match File::create(to) {
        Ok(ret) => ret,
        Err(e) => return Err(anyhow!("failed to create new backup file. {}", e)),
    };
    let encoder = GzEncoder::new(tgz, Compression::default());
    let mut tar = tar::Builder::new(encoder);
    tar.append_dir_all(DEFAULT_ZIP_DIR, from)
        .with_context(|| anyhow!("failed to write data into backup file"))?;
    tar.finish()
        .with_context(|| anyhow!("failed to finish backup"))?;
    Ok(())
}

/// unzip and untar backup file
/// # Errors
/// * fail to open tar.gz file
/// * fail to untar or unzip
fn untar_unzip(from: &PathBuf, to: &str) -> Result<(), anyhow::Error> {
    let tgz = File::open(from)?;
    let decoder = GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(to)?;
    Ok(())
}

/// # Errors
/// * fail to read path & metadata
fn detail_files(dir: &str, backup_list: &mut [BackupInfo]) -> Result<()> {
    if let Ok(paths) = fs::read_dir(dir) {
        for path in paths.flatten() {
            let filepath = path.path();
            let metadata = fs::metadata(filepath)?;
            if let Some(filename) = path.path().file_name() {
                if let Some(filename) = filename.to_str() {
                    if let Some((id, _)) = filename.split_once('.') {
                        if let Ok(id) = id.parse::<u32>() {
                            for backup in backup_list.iter_mut() {
                                if backup.id == id {
                                    backup.size += metadata.len();
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        fs::create_dir(dir)?;
    }
    Ok(())
}

/// # Errors
/// * fail to extract
fn restore_data(cfg: &BackupConfig, from: &PathBuf) -> Result<()> {
    // Create a folder to copy the current postgres DB folder to before restoring.
    let postgres_old_db_temp = format!("{}/{DEFAULT_TEMP_DIR}", cfg.review_data_path);
    if !Path::new(&postgres_old_db_temp).exists() && fs::create_dir(&postgres_old_db_temp).is_err()
    {
        return Err(anyhow!("Host backup temporary folder creation failed"));
    }

    let tmp_path = format!("{postgres_old_db_temp}/{DEFAULT_ZIP_DIR}");
    if Path::new(&tmp_path).exists() {
        remove_tmpdir_all(&tmp_path)?;
    }

    if extract_to(from, &postgres_old_db_temp).is_err() {
        return Err(anyhow!("backup file extraction failed"));
    }

    let postgres_dump = format!("{tmp_path}/{DEFAULT_POSTGRES_DUMP_FILE}");
    if Path::new(&postgres_dump).exists() {
        postgres_restore_docker(cfg, &postgres_dump, &postgres_old_db_temp)?;
    }
    remove_tmpdir_all(&tmp_path)?;
    Ok(())
}

/// # Errors
/// * fail to untar or unzip
fn extract_to(from: &PathBuf, to: &str) -> Result<()> {
    // extract backup file in "/tmp"
    untar_unzip(from, to)?;
    Ok(())
}
