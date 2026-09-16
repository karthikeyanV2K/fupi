use crate::types::FlashState;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StorageError {
    IoError(io::Error),
    JsonError(serde_json::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "Storage IO error: {e}"),
            StorageError::JsonError(e) => write!(f, "Storage JSON parse error: {e}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::IoError(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::JsonError(e)
    }
}

#[derive(Debug, Clone)]
pub struct FlashStorage {
    path: PathBuf,
}

impl FlashStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<FlashState, StorageError> {
        let tmp_path = self.path.with_extension("tmp");
        let bak_path = self.path.with_extension("bak");

        // 1. If primary path does not exist, check if an interrupted rename left a valid .tmp file
        if !self.path.exists() {
            if tmp_path.exists() {
                if let Ok(content) = fs::read_to_string(&tmp_path) {
                    if let Ok(state) = serde_json::from_str::<FlashState>(&content) {
                        let _ = fs::rename(&tmp_path, &self.path);
                        return Ok(state);
                    }
                }
            }
            if bak_path.exists() {
                if let Ok(content) = fs::read_to_string(&bak_path) {
                    if let Ok(state) = serde_json::from_str::<FlashState>(&content) {
                        let _ = fs::copy(&bak_path, &self.path);
                        return Ok(state);
                    }
                }
            }
            return Ok(FlashState::default());
        }

        // 2. Primary path exists: read content
        let content = match fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) => return Err(StorageError::IoError(e)),
        };

        // If content is empty or corrupt, attempt recovery from .tmp or .bak before wiping!
        if content.trim().is_empty() {
            if tmp_path.exists() {
                if let Ok(t_content) = fs::read_to_string(&tmp_path) {
                    if let Ok(state) = serde_json::from_str::<FlashState>(&t_content) {
                        let _ = fs::rename(&tmp_path, &self.path);
                        return Ok(state);
                    }
                }
            }
            if bak_path.exists() {
                if let Ok(b_content) = fs::read_to_string(&bak_path) {
                    if let Ok(state) = serde_json::from_str::<FlashState>(&b_content) {
                        let _ = fs::copy(&bak_path, &self.path);
                        return Ok(state);
                    }
                }
            }
            return Ok(FlashState::default());
        }

        match serde_json::from_str(&content) {
            Ok(state) => Ok(state),
            Err(orig_err) => {
                // If primary file has invalid JSON (e.g. power cut during write), attempt recovery from .tmp or .bak
                if tmp_path.exists() {
                    if let Ok(t_content) = fs::read_to_string(&tmp_path) {
                        if let Ok(state) = serde_json::from_str::<FlashState>(&t_content) {
                            let _ = fs::rename(&tmp_path, &self.path);
                            return Ok(state);
                        }
                    }
                }
                if bak_path.exists() {
                    if let Ok(b_content) = fs::read_to_string(&bak_path) {
                        if let Ok(state) = serde_json::from_str::<FlashState>(&b_content) {
                            let _ = fs::copy(&bak_path, &self.path);
                            return Ok(state);
                        }
                    }
                }
                Err(StorageError::JsonError(orig_err))
            }
        }
    }

    /// Atomically persists state to flash:
    /// writes to temporary file, flushes to disk, creates .bak backup, and renames over destination.
    /// Crucial for embedded RPi to avoid file corruption on unexpected power cuts.
    pub fn save(&self, state: &FlashState) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let tmp_path = self.path.with_extension("tmp");
        let bak_path = self.path.with_extension("bak");

        // 1. Write and flush to temporary file
        {
            let mut file = File::create(&tmp_path)?;
            let data = serde_json::to_vec_pretty(state)?;
            file.write_all(&data)?;
            file.sync_all()?;
        }

        // 2. Ensure backup copy exists with the synced data
        let _ = fs::copy(&tmp_path, &bak_path);

        // 3. Atomically rename .tmp over destination
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    pub fn wipe(&self) -> Result<(), StorageError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        let tmp_path = self.path.with_extension("tmp");
        if tmp_path.exists() {
            let _ = fs::remove_file(&tmp_path);
        }
        let bak_path = self.path.with_extension("bak");
        if bak_path.exists() {
            let _ = fs::remove_file(&bak_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Proof;

    #[test]
    fn test_storage_lifecycle() {
        let test_file = std::env::temp_dir().join(format!("fupi_test_flash_{}.json", rand::random::<u32>()));
        let storage = FlashStorage::new(&test_file);

        // Load non-existent
        let empty = storage.load().unwrap();
        assert_eq!(empty.proofs.len(), 0);

        // Save state
        let mut state = FlashState::default();
        state.proofs.push(Proof {
            secret: "fupi-test".to_string(),
            sig: "sig".to_string(),
            n: "n".to_string(),
            e: 65537,
            keyset_id: Some("test-00".to_string()),
            p2pk: None,
            claimer: None,
        });
        state.journal.push("topup +1".to_string());
        storage.save(&state).unwrap();

        // Load persisted
        let loaded = storage.load().unwrap();
        assert_eq!(loaded.proofs.len(), 1);
        assert_eq!(loaded.journal.len(), 1);
        assert_eq!(loaded.proofs[0].secret, "fupi-test");

        // Wipe
        storage.wipe().unwrap();
        assert!(!test_file.exists());
    }

    #[test]
    fn test_storage_recovery_from_corrupted_primary_file() {
        let test_file = std::env::temp_dir().join(format!("fupi_test_corrupt_{}.json", rand::random::<u32>()));
        let storage = FlashStorage::new(&test_file);

        // 1. Save valid state
        let mut state = FlashState::default();
        state.proofs.push(Proof {
            secret: "fupi-valuable-cash".to_string(),
            sig: "valid-sig".to_string(),
            n: "modulus".to_string(),
            e: 65537,
            keyset_id: Some("go-mvp-00".to_string()),
            p2pk: None,
            claimer: None,
        });
        storage.save(&state).unwrap();

        // 2. Corrupt the primary file (simulate power cut during direct write / truncated to 0 bytes)
        fs::write(&test_file, b"").unwrap();

        // 3. Load should recover from .bak!
        let recovered = storage.load().expect("should recover from backup");
        assert_eq!(recovered.proofs.len(), 1);
        assert_eq!(recovered.proofs[0].secret, "fupi-valuable-cash");

        // Cleanup
        storage.wipe().unwrap();
    }
}
