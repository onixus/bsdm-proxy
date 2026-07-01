//! Tiered cache body storage: small responses inline, large bodies memory-mapped.

use bytes::Bytes;
use memmap2::Mmap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SPILL_SEQ: AtomicU64 = AtomicU64::new(0);

/// Create `CACHE_SPILL_DIR` if missing and restrict to owner-only (`0o700` on Unix).
pub fn ensure_private_spill_dir(spill_dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(spill_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(spill_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(spill_dir, perms)?;
    }
    Ok(())
}

fn open_new_spill_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Owns a spill file, its mmap mapping, and removes the file on drop.
struct MmapOwner {
    _file: File,
    mmap: Mmap,
    path: PathBuf,
}

impl AsRef<[u8]> for MmapOwner {
    fn as_ref(&self) -> &[u8] {
        &self.mmap[..]
    }
}

impl Drop for MmapOwner {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Stored HTTP body — inline (small) or mmap-backed spill (large).
#[derive(Clone, Debug)]
pub enum CachedBody {
    Inline(Bytes),
    /// Zero-copy body backed by a mmap spill file (`Bytes::from_owner`).
    Mmap(Bytes),
}

impl CachedBody {
    pub fn inline(bytes: Bytes) -> Self {
        Self::Inline(bytes)
    }

    pub fn stored_len(&self) -> usize {
        match self {
            Self::Inline(b) | Self::Mmap(b) => b.len(),
        }
    }

    /// Load body bytes for serve / L2 wire (mmap uses zero-copy `Bytes::from_owner`).
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Inline(b) | Self::Mmap(b) => b.clone(),
        }
    }

    /// Write `data` to a spill file and mmap it read-only.
    pub fn spill(data: &[u8], spill_dir: &Path) -> std::io::Result<Self> {
        ensure_private_spill_dir(spill_dir)?;
        let id = SPILL_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = spill_dir.join(format!("body-{id:016x}.bin"));
        let spill_result: std::io::Result<Self> = (|| {
            {
                let mut file = open_new_spill_file(&path)?;
                file.write_all(data)?;
                file.sync_all()?;
            }
            let file = OpenOptions::new().read(true).open(&path)?;
            // SAFETY: file is not mutated after mmap; we own the file handle.
            let mmap = unsafe { Mmap::map(&file)? };
            let owner = MmapOwner {
                _file: file,
                mmap,
                path: path.clone(),
            };
            Ok(Self::Mmap(Bytes::from_owner(owner)))
        })();
        if spill_result.is_err() {
            let _ = fs::remove_file(&path);
        }
        spill_result
    }

    pub fn maybe_spill(data: Bytes, spill_dir: &Path, threshold: usize) -> std::io::Result<Self> {
        if threshold > 0 && data.len() >= threshold {
            Self::spill(data.as_ref(), spill_dir)
        } else {
            Ok(Self::inline(data))
        }
    }

    pub fn is_mmap(&self) -> bool {
        matches!(self, Self::Mmap(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn spill_roundtrip() {
        let dir = tempdir().unwrap();
        let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let body = CachedBody::spill(&payload, dir.path()).unwrap();
        assert!(body.is_mmap());
        assert_eq!(body.stored_len(), payload.len());
        assert_eq!(body.to_bytes().as_ref(), payload.as_slice());
    }

    #[test]
    fn maybe_spill_inline_below_threshold() {
        let dir = tempdir().unwrap();
        let b = Bytes::from_static(b"small");
        let body = CachedBody::maybe_spill(b.clone(), dir.path(), 1024).unwrap();
        assert!(!body.is_mmap());
    }

    #[test]
    fn ensure_private_spill_dir_restricts_mode() {
        let parent = tempdir().unwrap();
        let spill_dir = parent.path().join("spill");
        ensure_private_spill_dir(&spill_dir).unwrap();
        assert!(spill_dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&spill_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn spill_file_is_owner_read_write_only() {
        let dir = tempdir().unwrap();
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let _body = CachedBody::spill(&payload, dir.path()).unwrap();
        let spill_file = fs::read_dir(dir.path())
            .unwrap()
            .find_map(|e| e.ok())
            .expect("spill file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = spill_file.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        #[cfg(not(unix))]
        {
            let _ = spill_file;
        }
    }
}
