//! `impl FileSystem for UdfVfs` — the forensic-vfs adapter (behind the `vfs`
//! feature) so a UDF volume composes as `Arc<dyn FileSystem>` in the forensic-vfs
//! engine.
//!
//! [`UdfVfs`] wraps a parsed [`UdfState`] plus its backing `Read + Seek` source in
//! a `Mutex`, so every read is `&self` over interior mutability and one mounted
//! handle serves N workers (matching the iso9660/ext4/NTFS adapters). Nodes are
//! addressed by [`FileId::Opaque`] carrying the File Entry's physical LBA
//! (`fe_lba`) — UDF's node identity primitive. `forensic-vfs`'s `FileId` has no
//! dedicated UDF variant (it is `#[non_exhaustive]`, and this crate must not add
//! one), so `Opaque(fe_lba)` is the closest honest mapping.
//!
//! ## Mapping notes / known limits
//! - **No inode table ⇒ a per-FE record cache.** UDF carries a node's `is_dir`
//!   flag in its parent's File Identifier Descriptor, not at the node's own File
//!   Entry. [`FileSystem::read_dir`]/[`FileSystem::lookup`] cache each child by
//!   `fe_lba`; the root FE is seeded as a directory at [`UdfVfs::open`].
//!   [`FileSystem::meta`] consults that cache — the normal
//!   root→read_dir→lookup→stat flow always populates it. An *untraversed file*
//!   FE cannot be classified as file-vs-dir (a loud [`VfsError::Decode`], never a
//!   guess); the *root* FE is always resolvable (seeded).
//! - **Times.** The UDF reader's public traversal API surfaces only
//!   name/is_dir/size/fe_lba per child, not the per-File-Entry recording times,
//!   so [`FsMeta::times`] is all-`None` (honestly absent, not epoch-0). Wiring
//!   the FE modification/creation times through is future work.
//!   [`FileSystem::timestamp_zone`] is [`TimeZonePolicy::Utc`] — UDF ECMA-167
//!   timestamps carry an explicit UTC offset.
//! - **Single stream.** UDF has no alternate data streams; a non-`Default`
//!   [`StreamId`] is refused loud.
//! - **Extents (first cut).** The reader does not expose a File Entry's
//!   allocation descriptors through its public API, so [`FileSystem::extents`]
//!   yields a single logical run (`image_offset` = 0, `len` = file size) rather
//!   than the true on-disk runs. Surfacing the real short/long allocation
//!   descriptors is future work.
//! - **Deleted/unallocated/symlinks.** Orphan/deleted File Entry recovery and
//!   free-space enumeration are not yet surfaced, so
//!   [`FileSystem::deleted`]/[`FileSystem::unallocated`] are empty streams;
//!   UDF symlinks (PATH_COMPONENTS) are not decoded, so
//!   [`FileSystem::read_link`] returns an empty target. All three are future
//!   work, not fabricated data.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::{Mutex, MutexGuard, PoisonError};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem,
    FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, SmallHex, StreamId, TimeZonePolicy, VfsError, VfsResult,
};

use crate::{read_dir_at_lba, read_fe_data, read_fe_file_type, UdfState, FILE_TYPE_DIRECTORY};

/// Per-node metadata harvested from a parent File Identifier Descriptor and
/// cached by File Entry LBA.
#[derive(Clone, Copy)]
struct FeMeta {
    is_dir: bool,
    size: u64,
}

/// Reader plus its per-FE record cache, guarded by one mutex.
struct Inner<R> {
    reader: R,
    cache: HashMap<u32, FeMeta>,
}

/// A mounted UDF volume exposed through the forensic-vfs `FileSystem` contract.
/// Reads are `&self` over an interior `Mutex`, so one handle serves N workers.
pub struct UdfVfs<R: Read + Seek> {
    inner: Mutex<Inner<R>>,
    state: UdfState,
}

impl<R: Read + Seek + Send> UdfVfs<R> {
    /// Open a UDF volume over a `Read + Seek` cursor.
    ///
    /// Parses the AVDP → VDS → FSD bootstrap chain; the root directory's File
    /// Entry LBA (from the File Set Descriptor) seeds the per-FE cache as a
    /// directory so `meta(root())` resolves without a directory read.
    pub fn open(mut reader: R) -> VfsResult<Self> {
        let state = crate::parse_udf_state_checked(&mut reader)
            .map_err(|source| VfsError::Io {
                op: "udf bootstrap",
                source,
            })?
            .ok_or(VfsError::Bootstrap {
                stage: "udf mount",
                detail: "no valid UDF AVDP/VDS/FSD chain".to_string(),
            })?;
        let mut cache = HashMap::new();
        cache.insert(
            state.root_fe_lba,
            FeMeta {
                is_dir: true,
                size: 0,
            },
        );
        Ok(Self {
            inner: Mutex::new(Inner { reader, cache }),
            state,
        })
    }

    /// Lock the interior state, recovering from a poisoned mutex rather than
    /// panicking (Paranoid Gatekeeper).
    fn lock(&self) -> MutexGuard<'_, Inner<R>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The File Entry LBA carried by a [`FileId`]; any other identity domain is a
/// caller error surfaced loud.
fn fe_lba_of(id: FileId) -> VfsResult<u32> {
    match id {
        FileId::Opaque(n) => u32::try_from(n).map_err(|_| VfsError::Unsupported {
            layer: "udf file-id",
            scheme: format!("Opaque({n})"),
        }),
        other => Err(VfsError::Unsupported {
            layer: "udf file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// UDF exposes a single unnamed data stream; a named-stream id is refused loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "udf stream",
            scheme: format!("{other:?}"),
        }),
    }
}

impl<R: Read + Seek + Send> UdfVfs<R> {
    /// Resolve the cached `FeMeta` for `fe_lba`, or — for an uncached FE — read
    /// its File Entry, classify it from the ICB Tag File Type, and cache it. A
    /// sector that does not parse as a File Entry is a loud [`VfsError::Decode`]
    /// (an untraversed *file* extent has no cached record and no self-classifiable
    /// directory tag; UDF has no inode table, so it cannot be resolved).
    fn resolve(inner: &mut Inner<R>, fe_lba: u32, block_size: u32) -> VfsResult<FeMeta> {
        if let Some(m) = inner.cache.get(&fe_lba) {
            return Ok(*m);
        }
        match read_fe_file_type(&mut inner.reader, block_size, fe_lba) {
            Some(ft) => {
                let is_dir = ft == FILE_TYPE_DIRECTORY;
                let size =
                    crate::read_fe_info_len(&mut inner.reader, block_size, fe_lba).unwrap_or(0);
                let m = FeMeta { is_dir, size };
                inner.cache.insert(fe_lba, m);
                Ok(m)
            }
            None => Err(VfsError::Decode {
                layer: "udf",
                offset: u64::from(fe_lba) * u64::from(block_size),
                detail: format!(
                    "no File Entry at LBA {fe_lba}; enumerate its parent directory first"
                ),
                bytes: SmallHex::new(&[]),
            }),
        }
    }

    /// Read a directory's children, caching each child's `FeMeta`. A loud error
    /// if `fe_lba` is not a directory File Entry.
    fn dir_children(&self, fe_lba: u32) -> VfsResult<Vec<crate::UdfFileEntry>> {
        let block_size = self.state.block_size;
        let partition_start = self.state.partition_start;
        let mut inner = self.lock();
        // Classify first so a file (or a non-FE LBA) fails loud rather than
        // yielding an empty listing.
        let meta = Self::resolve(&mut inner, fe_lba, block_size)?;
        if !meta.is_dir {
            return Err(VfsError::Decode {
                layer: "udf",
                offset: u64::from(fe_lba) * u64::from(block_size),
                detail: format!("File Entry at LBA {fe_lba} is not a directory"),
                bytes: SmallHex::new(&[]),
            });
        }
        let children = read_dir_at_lba(&mut inner.reader, block_size, partition_start, fe_lba)
            .ok_or_else(|| VfsError::Decode {
                layer: "udf",
                offset: u64::from(fe_lba) * u64::from(block_size),
                detail: format!("directory File Entry at LBA {fe_lba} could not be read"),
                bytes: SmallHex::new(&[]),
            })?;
        for c in &children {
            inner.cache.insert(
                c.fe_lba,
                FeMeta {
                    is_dir: c.is_dir,
                    size: c.size,
                },
            );
        }
        Ok(children)
    }
}

impl<R: Read + Seek + Send> FileSystem for UdfVfs<R> {
    fn kind(&self) -> FsKind {
        FsKind::UDF
    }

    fn root(&self) -> FileId {
        FileId::Opaque(u64::from(self.state.root_fe_lba))
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: self.state.block_size,
            physical: self.state.block_size,
            cluster_or_block: self.state.block_size,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // ECMA-167 timestamps carry an explicit type/timezone; UDF's canonical
        // interchange time is UTC-anchored.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let fe_lba = fe_lba_of(ino)?;
        let children = self.dir_children(fe_lba)?;
        let out: Vec<VfsResult<VfsDirEntry>> = children
            .into_iter()
            .map(|c| {
                Ok(VfsDirEntry {
                    name: c.name.into_bytes(),
                    id: FileId::Opaque(u64::from(c.fe_lba)),
                    kind: if c.is_dir {
                        NodeKind::Dir
                    } else {
                        NodeKind::File
                    },
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let fe_lba = fe_lba_of(ino)?;
        require_default_stream(stream)?;
        let block_size = self.state.block_size;
        let mut inner = self.lock();
        let meta = Self::resolve(&mut inner, fe_lba, block_size)?;
        // First cut: the reader does not surface a File Entry's allocation
        // descriptors, so a non-empty node yields one logical run (image_offset 0)
        // rather than its true on-disk runs. See the module note.
        if meta.size == 0 {
            return Ok(ExtentStream::empty());
        }
        let run = RunInfo {
            run: ByteRun {
                image_offset: 0,
                len: meta.size,
                flags: RunFlags::default(),
            },
            alloc: RunAlloc::Allocated,
        };
        Ok(ExtentStream::new(std::iter::once(Ok(run))))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let fe_lba = fe_lba_of(parent)?;
        let children = self.dir_children(fe_lba)?;
        for c in &children {
            if name.eq_ignore_ascii_case(c.name.as_bytes()) {
                return Ok(Some(FileId::Opaque(u64::from(c.fe_lba))));
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let fe_lba = fe_lba_of(ino)?;
        let block_size = self.state.block_size;
        let mut inner = self.lock();
        let m = Self::resolve(&mut inner, fe_lba, block_size)?;
        Ok(FsMeta {
            ino: u64::from(fe_lba),
            kind: if m.is_dir {
                NodeKind::Dir
            } else {
                NodeKind::File
            },
            allocated: Allocation::Allocated,
            size: m.size,
            nlink: 1,
            uid: None,
            gid: None,
            mode: None,
            // The reader's public traversal API does not surface per-FE times;
            // honestly absent, not epoch-0 (see the module note).
            times: MacbTimes {
                modified: None,
                accessed: None,
                changed: None,
                born: None,
            },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let fe_lba = fe_lba_of(ino)?;
        require_default_stream(stream)?;
        let block_size = self.state.block_size;
        let partition_start = self.state.partition_start;
        let mut inner = self.lock();
        // Confirm the node resolves (loud on an untraversed file / non-FE LBA).
        Self::resolve(&mut inner, fe_lba, block_size)?;
        let Some(data) = read_fe_data(&mut inner.reader, block_size, partition_start, fe_lba)
        else {
            return Ok(0);
        };
        let Ok(start) = usize::try_from(off) else {
            return Ok(0);
        };
        if start >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - start).min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(start..start + n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    fn read_link(&self, ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // UDF PATH_COMPONENT symlinks are not decoded; a node reads as an empty
        // target (matching the iso9660/ext4/NTFS adapters), not a per-node error.
        let _ = fe_lba_of(ino)?;
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Orphan/deleted File Entry recovery is not yet surfaced.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_vfs::{Allocation, NodeKind, RunAlloc};
    use std::fs::File;

    /// The committed real `mkudffs` fixture: a Type-1 physical partition with a
    /// 512-byte logical block. It is the only fixture whose partition kind the
    /// reader fully resolves for data reads. See `tests/data/README.md`.
    const PLAIN: &str = "udf_plain.img";

    fn open_plain() -> Option<UdfVfs<File>> {
        let path = format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), PLAIN);
        let f = File::open(path).ok()?;
        UdfVfs::open(f).ok()
    }

    #[test]
    fn kind_root_and_zone() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        assert_eq!(fs.kind(), FsKind::UDF);
        assert!(matches!(fs.root(), FileId::Opaque(_)));
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
        let ss = fs.sector_sizes();
        assert_eq!(ss.logical, 512);
        assert_eq!(ss.cluster_or_block, 512);
        assert!(ss.physical >= 512);
        // root() is resolvable via meta without a directory read (seeded cache).
        let m = fs.meta(fs.root()).expect("root meta");
        assert_eq!(m.kind, NodeKind::Dir);
    }

    #[test]
    fn lists_root() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        let root = fs.root();
        let entries: Vec<_> = fs
            .read_dir(root)
            .expect("read_dir")
            .map(|e| e.expect("entry"))
            .collect();
        // The mkudffs plain image has an empty root by default; the contract is
        // that read_dir on the root directory succeeds (never errors) and every
        // yielded child carries an Opaque FileId.
        for e in &entries {
            assert!(matches!(e.id, FileId::Opaque(_)));
        }
    }

    #[test]
    fn root_extents_and_meta_shape() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        let m = fs.meta(fs.root()).expect("root meta");
        assert_eq!(m.allocated, Allocation::Allocated);
        assert_eq!(m.nlink, 1);
        assert!(m.times.modified.is_none());
        // extents on the root directory yields at most a single logical run.
        let runs: Vec<_> = fs
            .extents(fs.root(), StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert!(runs.len() <= 1);
        if let Some(r) = runs.first() {
            assert_eq!(r.alloc, RunAlloc::Allocated);
        }
    }

    #[test]
    fn read_at_with_offset() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        // The root directory's data is readable; reading past EOF yields 0.
        let mut buf = [0u8; 32];
        let n = fs
            .read_at(fs.root(), StreamId::Default, 0, &mut buf)
            .expect("read_at");
        assert!(n <= buf.len());
        assert_eq!(
            fs.read_at(fs.root(), StreamId::Default, u64::from(u32::MAX), &mut buf)
                .expect("eof read"),
            0
        );
    }

    #[test]
    fn empty_forensic_surfaces() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        assert_eq!(fs.deleted().unwrap().count(), 0);
        assert_eq!(fs.unallocated().unwrap().count(), 0);
        assert!(fs.read_link(fs.root(), 4096).unwrap().is_empty());
    }

    #[test]
    fn wrong_file_id_and_stream_are_loud() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        // A non-Opaque FileId is not a UDF node id.
        assert!(fs.meta(FileId::NtfsRef { entry: 5, seq: 1 }).is_err());
        assert!(fs.read_dir(FileId::NtfsRef { entry: 5, seq: 1 }).is_err());
        assert!(fs
            .lookup(FileId::NtfsRef { entry: 5, seq: 1 }, b"x")
            .is_err());
        assert!(fs
            .read_link(FileId::NtfsRef { entry: 5, seq: 1 }, 8)
            .is_err());
        // A named stream is refused.
        assert!(fs
            .read_at(fs.root(), StreamId::Named(1), 0, &mut [0u8; 4])
            .is_err());
        assert!(fs.extents(fs.root(), StreamId::Named(1)).is_err());
    }

    #[test]
    fn read_dir_on_a_file_is_loud() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        // An FE LBA that is not a directory (a bogus/never-traversed extent that
        // does not parse as a directory File Entry) fails loud, not silently.
        let bogus = FileId::Opaque(u64::from(u32::MAX));
        assert!(fs.read_dir(bogus).is_err());
    }

    #[test]
    fn meta_on_untraversed_file_is_loud() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        // A file FE never surfaced by read_dir/lookup cannot be stat'd (UDF has
        // no inode table); a loud error, never a guess.
        assert!(fs.meta(FileId::Opaque(9_999_999)).is_err());
    }

    #[test]
    fn lookup_missing_is_none() {
        let Some(fs) = open_plain() else {
            eprintln!("skip: {PLAIN} fixture absent");
            return;
        };
        assert!(fs.lookup(fs.root(), b"NOPE.NOTPRESENT").unwrap().is_none());
    }

    #[test]
    fn fe_lba_of_rejects_non_opaque_and_overflow() {
        assert!(super::fe_lba_of(FileId::Opaque(42)).is_ok());
        assert!(super::fe_lba_of(FileId::Opaque(u64::from(u32::MAX) + 1)).is_err());
        assert!(super::fe_lba_of(FileId::NtfsRef { entry: 1, seq: 1 }).is_err());
    }
}
