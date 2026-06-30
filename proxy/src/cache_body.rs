//! Tiered cache body storage: small responses inline, large bodies memory-mapped.

use bytes::Bytes;
use memmap2::Mmap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SPILL_SEQ: AtomicU64 = AtomicU64::new(0);

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
        fs::create_dir_all(spill_dir)?;
        let id = SPILL_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = spill_dir.join(format!("body-{id:016x}.bin"));
        {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            file.write_all(data)?;
            file.sync_all()?;
        }
        let file = OpenOptions::new().read(true).open(&path)?;
        // SAFETY: file is not mutated after mmap; we own the file handle.
        let mmap = unsafe { Mmap::map(&file)? };
        let owner = MmapOwner {
            _file: file,
            mmap,
            path,
        };
        Ok(Self::Mmap(Bytes::from_owner(owner)))
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
}
