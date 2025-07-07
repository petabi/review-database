use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tokio::fs as async_fs;

/// Manages classifier file storage in the file system using computed paths.
///
/// Stores classifier binary data in a hierarchical directory structure:
/// `base_dir/classifiers/model_{id}/classifier_{name}.bin`
pub struct ClassifierFileManager {
    base_dir: PathBuf,
}

impl ClassifierFileManager {
    /// Creates a new `ClassifierFileManager` with the specified base directory.
    /// The base directory will be created if it doesn't exist.
    ///
    /// # Errors
    ///
    /// If directory creation fails due to insufficient permissions,
    /// invalid path, I/O errors, etc. during directory creation.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .with_context(|| format!("Failed to create directories: {}", base_dir.display()))?;
        }

        Ok(Self { base_dir })
    }

    /// Creates the file system path for a classifier based on model id and name.
    ///
    /// This is a pure function that generates deterministic paths without checking
    /// if the file actually exists. The path structure is:
    /// `{base_dir}/classifiers/model_{model_id}/classifier_{name}.bin`
    #[must_use]
    pub fn create_classifier_path(&self, model_id: i32, name: &str) -> PathBuf {
        self.base_dir
            .join("classifiers")
            .join(format!("model_{model_id}"))
            .join(format!("classifier_{name}.bin"))
    }

    /// Stores classifier data to the file system.
    ///
    /// Data is first written to a temporary file with a unique timestamp
    /// extension, then renamed to the final location.
    ///
    /// Note that since `REview` only supports a single `REconverge`, it is
    /// highly unlikely that `review-database` receives multiple write requests
    /// for the same classifier simultaneously.
    ///
    /// # Errors
    ///
    /// If storage fails due to insufficient disk space, permission denied, I/O
    /// errors during directory creation, file write, or rename, or concurrent
    /// access conflicts (rare with timestamp-based temp files), etc.
    pub async fn store_classifier(&self, model_id: i32, name: &str, data: &[u8]) -> Result<()> {
        let file_path = self.create_classifier_path(model_id, name);

        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            async_fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "Failed to create parent directories: {}",
                    file_path.display()
                )
            })?;
        }

        let timestamp = chrono::Utc::now().timestamp_millis();
        let temp_path = file_path.with_extension(timestamp.to_string());

        // Write to temporary file first
        async_fs::write(&temp_path, data)
            .await
            .context("Failed to write temp classifier file")?;

        // Rename to final location
        if let Err(e) = async_fs::rename(&temp_path, &file_path).await {
            // Clean up temp file on failure
            match async_fs::remove_file(&temp_path).await {
                Ok(()) => bail!("Failed to rename temp classifier file: {e}"),
                Err(err) => {
                    bail!("Failed to rename and remove temp classifier file: {e}, {err}")
                }
            }
        }

        Ok(())
    }

    /// Loads classifier data from the file system.
    ///
    /// If the classifier file doesn't exist, returns an empty Vec rather than
    /// an error. This allows graceful handling of missing classifiers.
    ///
    /// # Errors
    ///
    /// If loading fails due to permission denied, I/O errors, corrupted file, etc.
    pub async fn load_classifier(&self, model_id: i32, name: &str) -> Result<Vec<u8>> {
        let file_path = self.create_classifier_path(model_id, name);

        // Return empty vector if file doesn't exist
        if !file_path.exists() {
            return Ok(Vec::new());
        }

        async_fs::read(&file_path)
            .await
            .with_context(|| format!("Failed to load classifier file: {}", file_path.display()))
    }

    /// Checks if a classifier file exists without loading it.
    ///
    /// This is a synchronous operation that only checks file existence,
    /// not readability or integrity. The file might exist but be unreadable
    /// due to permission issues.
    #[must_use]
    pub fn classifier_exists(&self, model_id: i32, name: &str) -> bool {
        self.create_classifier_path(model_id, name).exists()
    }

    /// Deletes a classifier file from the file system.
    ///
    /// If the file doesn't exist, this operation succeeds silently.
    ///
    /// # Errors
    ///
    /// If deletion fails due to permission denied, I/O errors, etc.
    pub async fn delete_classifier(&self, model_id: i32, name: &str) -> Result<()> {
        let file_path = self.create_classifier_path(model_id, name);

        // Only attempt deletion if file exists
        if file_path.exists() {
            async_fs::remove_file(&file_path).await.with_context(|| {
                format!("Failed to remove classifier file: {}", file_path.display())
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_new_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("test_base");

        assert!(!base_path.exists());

        let manager = ClassifierFileManager::new(&base_path).unwrap();

        assert!(base_path.exists());
        assert_eq!(manager.base_dir, base_path);
    }

    #[test]
    fn test_new_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        assert!(base_path.exists());

        let manager = ClassifierFileManager::new(base_path).unwrap();

        assert_eq!(manager.base_dir, base_path);
    }

    #[test]
    fn test_create_classifier_path() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let path = manager.create_classifier_path(123, "test_classifier");
        let expected = temp_dir
            .path()
            .join("classifiers")
            .join("model_123")
            .join("classifier_test_classifier.bin");

        assert_eq!(path, expected);
    }

    #[tokio::test]
    async fn test_store_and_load_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let test_data = b"test classifier data";
        let model_id = 456;
        let name = "test_model";

        manager
            .store_classifier(model_id, name, test_data)
            .await
            .unwrap();

        let loaded_data = manager.load_classifier(model_id, name).await.unwrap();
        assert_eq!(loaded_data, test_data);
    }

    #[tokio::test]
    async fn test_load_nonexistent_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let loaded_data = manager.load_classifier(999, "nonexistent").await.unwrap();
        assert!(loaded_data.is_empty());
    }

    #[test]
    fn test_classifier_exists() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        assert!(!manager.classifier_exists(123, "test"));

        let path = manager.create_classifier_path(123, "test");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"test data").unwrap();

        assert!(manager.classifier_exists(123, "test"));
    }

    #[tokio::test]
    async fn test_delete_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 789;
        let name = "delete_test";
        let test_data = b"data to delete";

        manager
            .store_classifier(model_id, name, test_data)
            .await
            .unwrap();
        assert!(manager.classifier_exists(model_id, name));

        manager.delete_classifier(model_id, name).await.unwrap();
        assert!(!manager.classifier_exists(model_id, name));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let result = manager.delete_classifier(999, "nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_store_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 111;
        let name = "nested_test";
        let test_data = b"nested data";

        manager
            .store_classifier(model_id, name, test_data)
            .await
            .unwrap();

        let expected_parent = temp_dir.path().join("classifiers").join("model_111");
        assert!(expected_parent.exists());

        let loaded_data = manager.load_classifier(model_id, name).await.unwrap();
        assert_eq!(loaded_data, test_data);
    }
}
