//! UDF (Universal Disk Format) — detection and file-entry traversal.
//!
//! UDF bridge discs carry both ISO 9660 and UDF structures on the same sectors.
//! The UDF recognition sequence starts at sector 16: each Volume Structure
//! Descriptor is 2048 bytes with a 5-byte identifier at bytes 1-5.
//!
//! Identifiers: "BEA01" (Extended Area Descriptor), "NSR02" or "NSR03"
//! (OSTA CS0 UDF mark), "TEA01" (Terminating Extended Area Descriptor).
//! NSR02/NSR03 presence is the definitive UDF indicator.
//!
//! # Full UDF traversal
//!
//! Descriptor chain: AVDP (LBA 256) → VDS → Partition Descriptor (partition
//! start LBA) + Logical Volume Descriptor (FSD location) → File Set Descriptor
//! (root dir FE LBA) → File Entry → File Identifier Descriptors.
//!
//! All physical LBAs satisfy: `phys_lba = partition_start + logical_block_num`.

use std::io::{self, Read, Seek, SeekFrom};

pub mod findings;

/// The canonical 5-level severity scale, re-exported at the crate root for
/// convenience (the analyzer grades every finding on it).
pub use forensicnomicon::report::Severity;

// ── ECMA-167 / UDF tag identifiers ───────────────────────────────────────────

const TAG_AVDP: u16 = 2;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TERM: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_FE: u16 = 260;
/// Some UDF implementations (e.g. older genisoimage) write 261 for File Entry.
const TAG_FE_ALT: u16 = 261;
const TAG_EFE: u16 = 266;

// FID File Characteristics bits
const FC_DIRECTORY: u8 = 0x02;
const FC_PARENT: u8 = 0x08;

// ICB allocation type (FE flags bits 0-2)
const ALLOC_SHORT: u16 = 0;
const ALLOC_LONG: u16 = 1;
const ALLOC_INLINE: u16 = 3;

// Extent type bits 30-31 of extent_length field
const EXTENT_RECORDED: u32 = 0x0000_0000; // 0b00 in bits 30-31

// ── Logical block size ────────────────────────────────────────────────────────

/// Largest logical block size we read into a stack sector buffer.
const MAX_BLOCK_SIZE: usize = 4096;

/// Candidate UDF logical block sizes, most-common first. Optical media (CD/DVD/
/// BD) use 2048; hard-disk and USB UDF use 512; Advanced-Format media use 4096.
const BLOCK_SIZE_CANDIDATES: [u32; 4] = [2048, 512, 1024, 4096];

// ── Public types ──────────────────────────────────────────────────────────────

/// A single entry returned by UDF directory traversal.
#[derive(Debug, Clone)]
pub struct UdfFileEntry {
    /// Decoded filename (OSTA CS0: UTF-8 or UTF-16BE).
    pub name: String,
    /// True if this entry is a directory.
    pub is_dir: bool,
    /// File size in bytes (Information Length from FE).
    pub size: u64,
    /// Physical LBA of the File Entry descriptor sector.
    pub fe_lba: u32,
}

// ── Partition map kinds (ECMA-167 §10.7, OSTA UDF §2.2.8) ────────────────────

/// The kind of partition referenced by the UDF logical volume's file set.
///
/// `Physical` (Type 1) partitions resolve as `partition_start + logical_block`.
/// `Virtual` (VAT), `Sparable` (defect-managed), and `Metadata` (UDF 2.50+,
/// used by Blu-ray) are Type 2 partitions whose block resolution requires
/// additional structures this crate does not yet follow — they are detected
/// and reported so a forensic tool fails loudly rather than mis-reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UdfPartitionKind {
    /// Type 1 physical partition.
    Physical,
    /// Type 2 `*UDF Virtual Partition` (VAT-mapped, packet-written media).
    Virtual,
    /// Type 2 `*UDF Sparable Partition` (defect management).
    Sparable,
    /// Type 2 `*UDF Metadata Partition` (UDF 2.50+, Blu-ray).
    Metadata,
    /// Type 2 partition with an unrecognised identifier.
    Unknown,
}

// ── Internal UDF state ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct UdfState {
    pub partition_start: u32,
    pub root_fe_lba: u32,
    pub partition_kind: UdfPartitionKind,
    pub partition_map_count: u32,
    /// The medium's logical block size in bytes (512, 1024, 2048, or 4096),
    /// detected from the Anchor Volume Descriptor Pointer location rather than
    /// assumed — optical UDF is 2048-byte, but hard-disk media is 512-byte.
    pub block_size: u32,
    /// Physical LBA of the File Set Descriptor (`partition_start` + its logical
    /// block). The findings analyzer reads its recording time and validates its
    /// descriptor tag.
    pub fsd_lba: u32,
    /// Logical sector where the Volume Descriptor Sequence begins (from the
    /// AVDP). The findings analyzer re-walks the VDS to validate each
    /// descriptor's tag.
    pub vds_loc: u32,
    /// Length of the Volume Descriptor Sequence in whole logical blocks.
    pub vds_len_sectors: u32,
}

// ── UDF detection (existing public API) ──────────────────────────────────────

/// True if the image has a UDF recognition sequence (NSR02 or NSR03).
///
/// Scans volume structure descriptors starting at LBA 16, up to LBA 32.
pub fn detect_udf<R: Read + Seek>(reader: &mut R) -> bool {
    let mut buf = [0u8; 6];
    for lba in 16u64..32 {
        let pos = lba * 2048 + 1;
        if reader.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        let id = &buf[..5];
        if id == b"NSR02" || id == b"NSR03" {
            return true;
        }
        if id == b"TEA01" {
            break;
        }
    }
    false
}

// ── UDF traversal (new internal API) ─────────────────────────────────────────

/// Try to parse the AVDP → VDS → FSD chain, returning state needed for
/// directory traversal. Returns `None` if the image lacks a valid UDF structure.
///
/// Lenient wrapper over [`parse_udf_state_checked`]: a real seek/read I/O error
/// reading the anchor/VDS/FSD is folded into `None`, indistinguishable from a
/// structural "not UDF". Use [`parse_udf_state_checked`] when a truncated or
/// unreadable image must be told apart from a genuine non-UDF source.
pub fn parse_udf_state<R: Read + Seek>(reader: &mut R) -> Option<UdfState> {
    parse_udf_state_checked(reader).ok().flatten()
}

/// Parse the AVDP → VDS → FSD bootstrap chain, distinguishing a real read
/// failure from a structural negative.
///
/// - `Err(io)` — a seek/read I/O error reading the anchor (LBA 256), the Volume
///   Descriptor Sequence, or the File Set Descriptor. This includes
///   [`io::ErrorKind::UnexpectedEof`] when the image is truncated before the
///   anchor, which is itself forensically suspicious and must surface rather
///   than masquerade as "not UDF".
/// - `Ok(None)` — every read succeeded but the structure is not valid UDF (the
///   anchor tag is not an AVDP, or the descriptor chain is absent/incoherent).
///   This is the legitimate "not UDF" case.
/// - `Ok(Some(state))` — a valid UDF structure.
pub fn parse_udf_state_checked<R: Read + Seek>(
    reader: &mut R,
) -> Result<Option<UdfState>, io::Error> {
    let Some(block_size) = detect_block_size(reader)? else {
        return Ok(None);
    };
    let Some((vds_loc, vds_len)) = read_avdp_checked(reader, block_size)? else {
        return Ok(None);
    };
    let Some(vds) = read_vds_checked(reader, block_size, vds_loc, vds_len)? else {
        return Ok(None);
    };
    let Some(root_fe_lba) = read_fsd_checked(reader, block_size, vds.fsd_lba, vds.partition_start)?
    else {
        return Ok(None);
    };
    Ok(Some(UdfState {
        partition_start: vds.partition_start,
        root_fe_lba,
        partition_kind: vds.partition_kind,
        partition_map_count: vds.map_count,
        block_size,
        fsd_lba: vds.fsd_lba,
        vds_loc,
        vds_len_sectors: (vds_len as usize).div_ceil(block_size as usize) as u32,
    }))
}

/// Resolved Volume Descriptor Sequence information.
struct VdsInfo {
    partition_start: u32,
    fsd_lba: u32,
    partition_kind: UdfPartitionKind,
    map_count: u32,
}

/// A parsed partition map entry from the Logical Volume Descriptor.
struct PartitionMap {
    kind: UdfPartitionKind,
    /// Partition number (Type 1 only); `None` for Type 2 maps.
    partition_number: Option<u16>,
}

/// Classify a Type 2 partition map by scanning its identifier region for the
/// OSTA UDF entity strings.
fn classify_type2(map: &[u8]) -> UdfPartitionKind {
    let scan = |needle: &[u8]| map.windows(needle.len()).any(|w| w == needle);
    if scan(b"*UDF Metadata Partition") {
        UdfPartitionKind::Metadata
    } else if scan(b"*UDF Virtual Partition") {
        UdfPartitionKind::Virtual
    } else if scan(b"*UDF Sparable Partition") {
        UdfPartitionKind::Sparable
    } else {
        UdfPartitionKind::Unknown
    }
}

/// Parse the partition maps from a Logical Volume Descriptor sector.
///
/// LVD (ECMA-167 §10.6): N_PM at BP 268, Map Table Length at BP 264, maps at
/// BP 440.  Each map: `[type(1)][length(1)]…`; Type 1 carries the partition
/// number at RBP 4; Type 2 is identified by its embedded entity string.
fn parse_partition_maps(lvd: &[u8]) -> Vec<PartitionMap> {
    let n_pm = u32::from_le_bytes(lvd[268..272].try_into().unwrap()) as usize;
    let mt_l = u32::from_le_bytes(lvd[264..268].try_into().unwrap()) as usize;
    let maps_end = (440 + mt_l).min(lvd.len());
    let mut out = Vec::new();
    let mut off = 440;
    while out.len() < n_pm && off + 2 <= maps_end {
        let map_type = lvd[off];
        let map_len = lvd[off + 1] as usize;
        if map_len < 2 || off + map_len > maps_end {
            break;
        }
        let map = &lvd[off..off + map_len];
        let pm = match map_type {
            1 if map_len >= 6 => PartitionMap {
                kind: UdfPartitionKind::Physical,
                partition_number: Some(u16::from_le_bytes([map[4], map[5]])),
            },
            2 => PartitionMap {
                kind: classify_type2(map),
                partition_number: None,
            },
            _ => PartitionMap {
                kind: UdfPartitionKind::Unknown,
                partition_number: None,
            },
        };
        out.push(pm);
        off += map_len;
    }
    out
}

/// Read all non-parent File Identifier Descriptors from the directory whose
/// File Entry resides at `dir_fe_lba`, returning one `UdfFileEntry` per child.
pub fn read_dir_at_lba<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    dir_fe_lba: u32,
) -> Option<Vec<UdfFileEntry>> {
    let dir_data = read_fe_data(reader, block_size, partition_start, dir_fe_lba)?;
    Some(parse_fids(reader, block_size, partition_start, &dir_data))
}

/// Read the data extent of the File Entry at `fe_lba`.
pub fn read_fe_data<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    fe_lba: u32,
) -> Option<Vec<u8>> {
    let mut sector = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut sector[..block_size as usize];
    seek_read(reader, fe_lba as u64 * block_size as u64, sector)?;

    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    let is_efe = tag_ident == TAG_EFE;
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && !is_efe {
        return None;
    }

    let icb_flags = u16::from_le_bytes([sector[34], sector[35]]);
    let alloc_type = icb_flags & 0x0007;
    let info_len = u64::from_le_bytes(sector[56..64].try_into().unwrap());

    // EFE has an additional ObjectSize (8 bytes) field before L_EA / L_AD.
    let (ea_off, ad_off, header) = if is_efe {
        (176usize, 180usize, 184usize)
    } else {
        (168usize, 172usize, 176usize)
    };

    if ad_off + 4 > sector.len() {
        return None;
    }
    let ea_len = u32::from_le_bytes(sector[ea_off..ea_off + 4].try_into().unwrap()) as usize;
    let ad_len = u32::from_le_bytes(sector[ad_off..ad_off + 4].try_into().unwrap()) as usize;

    let ad_start = header + ea_len;
    let ad_end = ad_start + ad_len;
    if ad_end > sector.len() {
        return None;
    }
    let ad_area = sector[ad_start..ad_end].to_vec();

    match alloc_type {
        ALLOC_INLINE => Some(ad_area[..info_len.min(ad_area.len() as u64) as usize].to_vec()),
        ALLOC_SHORT => read_extents_short(reader, block_size, partition_start, &ad_area, info_len),
        ALLOC_LONG => read_extents_long(reader, block_size, partition_start, &ad_area, info_len),
        _ => None,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Detect the medium's logical block size by locating the Anchor Volume
/// Descriptor Pointer (ECMA-167 §3 / OSTA UDF §2.2.3): the AVDP sits at logical
/// sector 256, so for each candidate block size `bs` the anchor is at byte
/// `256 * bs`. A candidate is accepted when that sector carries the AVDP tag
/// identifier (2) AND the descriptor tag's recorded location field equals 256 —
/// the location check rules out a stray `0x0002` at the wrong probe offset.
///
/// Truncation handling mirrors [`read_avdp_checked`]: if *no* candidate's anchor
/// was even large enough to read (every probe hit `UnexpectedEof`), the image is
/// truncated before any possible AVDP and that surfaces as `Err`; if some probe
/// read but none matched, the source is readable-but-not-UDF (`Ok(None)`).
fn detect_block_size<R: Read + Seek>(reader: &mut R) -> Result<Option<u32>, io::Error> {
    let mut tag = [0u8; 16];
    let mut last_eof: Option<io::Error> = None;
    let mut any_read_ok = false;
    for bs in BLOCK_SIZE_CANDIDATES {
        match seek_read_checked(reader, 256 * bs as u64, &mut tag) {
            Ok(()) => {
                any_read_ok = true;
                let tag_ident = u16::from_le_bytes([tag[0], tag[1]]);
                let tag_location = u32::from_le_bytes(tag[12..16].try_into().unwrap());
                if tag_ident == TAG_AVDP && tag_location == 256 {
                    return Ok(Some(bs));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => last_eof = Some(e),
            Err(e) => return Err(e),
        }
    }
    if !any_read_ok {
        if let Some(e) = last_eof {
            return Err(e);
        }
    }
    Ok(None)
}

/// Parse the AVDP at logical sector 256 (`256 * block_size` bytes). `Err` on a
/// read I/O failure, `Ok(None)` when the anchor read succeeds but is not an
/// AVDP, `Ok(Some((vds_loc, vds_len)))` when the anchor is valid.
fn read_avdp_checked<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
) -> Result<Option<(u32, u32)>, io::Error> {
    let mut sector = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut sector[..block_size as usize];
    seek_read_checked(reader, 256 * block_size as u64, sector)?;
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_AVDP {
        return Ok(None);
    }
    let vds_len = u32::from_le_bytes(sector[16..20].try_into().unwrap());
    let vds_loc = u32::from_le_bytes(sector[20..24].try_into().unwrap());
    Ok(Some((vds_loc, vds_len)))
}

/// Scan the Volume Descriptor Sequence: collect every Partition Descriptor
/// (partition number → starting location) and the Logical Volume Descriptor
/// (file-set location, partition reference, and partition maps), then resolve
/// the file set's partition through its map.
fn read_vds_checked<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    vds_loc: u32,
    vds_len: u32,
) -> Result<Option<VdsInfo>, io::Error> {
    use std::collections::HashMap;
    let sectors = (vds_len as usize).div_ceil(block_size as usize);

    // partition number → starting location (physical LBA).
    let mut pd_start: HashMap<u16, u32> = HashMap::new();
    let mut fsd_lbn: Option<u32> = None;
    let mut fsd_part_ref: u16 = 0;
    let mut maps: Vec<PartitionMap> = Vec::new();

    for i in 0..sectors {
        let mut sector = [0u8; MAX_BLOCK_SIZE];
        let sector = &mut sector[..block_size as usize];
        seek_read_checked(
            reader,
            (vds_loc as u64 + i as u64) * block_size as u64,
            sector,
        )?;
        let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
        match tag_ident {
            TAG_PD => {
                let part_num = u16::from_le_bytes([sector[22], sector[23]]);
                let psl = u32::from_le_bytes(sector[188..192].try_into().unwrap());
                pd_start.insert(part_num, psl);
            }
            TAG_LVD => {
                // LV Contents Use long_ad at offset 248: extent_length [248..252],
                // logical_block_num [252..256], partition_reference [256..258].
                fsd_lbn = Some(u32::from_le_bytes(sector[252..256].try_into().unwrap()));
                fsd_part_ref = u16::from_le_bytes([sector[256], sector[257]]);
                maps = parse_partition_maps(sector);
            }
            TAG_TERM | 0 => break,
            _ => {}
        }
    }

    // Reads all succeeded; a missing LVD / unresolvable partition is structural.
    let Some(fsd) = fsd_lbn else {
        return Ok(None);
    };
    let map_count = maps.len() as u32;

    // Resolve the file set's partition via the referenced partition map.
    let referenced = maps.get(fsd_part_ref as usize);
    let kind = referenced.map_or(UdfPartitionKind::Unknown, |m| m.kind);

    // Type 1: resolve the partition start from the map's partition number.
    // Type 2 (Virtual/Sparable/Metadata): block resolution needs structures we
    // do not yet follow — fall back to the first physical partition so detection
    // still works, and report the kind so callers know reads may be incomplete.
    let partition_start = referenced
        .and_then(|m| m.partition_number)
        .and_then(|pn| pd_start.get(&pn).copied())
        .or_else(|| pd_start.values().min().copied());
    let Some(partition_start) = partition_start else {
        return Ok(None);
    };

    Ok(Some(VdsInfo {
        partition_start,
        fsd_lba: partition_start + fsd,
        partition_kind: kind,
        map_count,
    }))
}

/// Parse FSD at `fsd_lba` to find the root directory FE logical block number.
/// `Err` on a read I/O failure, `Ok(None)` when the FSD read succeeds but its
/// tag is not an FSD, `Ok(Some(root_fe_lba))` when the FSD is valid.
fn read_fsd_checked<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    fsd_lba: u32,
    partition_start: u32,
) -> Result<Option<u32>, io::Error> {
    let mut sector = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut sector[..block_size as usize];
    seek_read_checked(reader, fsd_lba as u64 * block_size as u64, sector)?;
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_FSD {
        return Ok(None);
    }
    // FSD field sizes (ECMA-167 Table 20):
    //   Tag(16) + RecordingDate(12) + Interchange/Charset fields(28) +
    //   LV Ident CharSet(64) + LV Identifier(128) + FS CharSet(64) +
    //   FS Identifier(32) + Copyright FI(32) + Abstract FI(32) = 408 bytes.
    // Root Directory ICB (long_ad) starts at offset 400:
    //   extent_length [400..404], logical_block_num [404..408]
    let lbn = u32::from_le_bytes(sector[404..408].try_into().unwrap());
    Ok(Some(partition_start + lbn))
}

/// Detect whether FIDs in this directory data use a standard 16-byte ECMA-167 tag
/// or an extended 18-byte tag written by some UDF tools.
///
/// Some implementations append 2 extra bytes after the standard tag before the
/// FID body, making all field offsets shift by 2. Detection heuristic: read the
/// ICB logical block number at both candidate positions and use whichever gives a
/// plausible value (< 65536, fitting discs up to ~128 GB).
fn detect_fid_tag_size(data: &[u8]) -> usize {
    let mut off = 0;
    while off + 28 <= data.len() {
        let ti = u16::from_le_bytes([data[off], data[off + 1]]);
        if ti == TAG_FID {
            let lbn16 = if off + 26 <= data.len() {
                u32::from_le_bytes(data[off + 22..off + 26].try_into().unwrap())
            } else {
                u32::MAX
            };
            let lbn18 = if off + 28 <= data.len() {
                u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap())
            } else {
                u32::MAX
            };
            if lbn16 < 0x10000 {
                return 16;
            }
            if lbn18 < 0x10000 {
                return 18;
            }
            return 16; // can't determine; fall back to standard
        }
        off += 4;
    }
    16
}

/// Parse File Identifier Descriptors from raw directory data.
fn parse_fids<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    data: &[u8],
) -> Vec<UdfFileEntry> {
    // Some UDF tools write an extra 2 bytes after the standard 16-byte tag.
    // tag_size is 16 (standard) or 18 (extended); body fields follow at tag_size.
    let tag_size = detect_fid_tag_size(data);
    let min_fid = tag_size + 20; // tag + chars(1)+L_FI(1)+ICB(16)+L_IU(2)

    let mut entries = Vec::new();
    let mut off = 0;

    while off + min_fid <= data.len() {
        let tag_ident = u16::from_le_bytes([data[off], data[off + 1]]);
        if tag_ident != TAG_FID {
            // Advance 4 bytes to stay aligned; skip padding or unknown tags.
            off += 4;
            continue;
        }

        // CRC_len (at tag[10..12]) gives the true body extent from byte 16.
        let crc_len = u16::from_le_bytes([data[off + 10], data[off + 11]]) as usize;
        let fid_advance = ((16 + crc_len + 3) & !3).max(min_fid);
        if off + fid_advance > data.len() {
            break;
        }

        let file_chars = data[off + tag_size];
        let file_id_len = data[off + tag_size + 1] as usize;
        // ICB long_ad: extent_length at body[2..6], lbn at body[6..10]
        let icb_lbn = if off + tag_size + 10 <= data.len() {
            u32::from_le_bytes(
                data[off + tag_size + 6..off + tag_size + 10]
                    .try_into()
                    .unwrap(),
            )
        } else {
            off += fid_advance.max(4);
            continue;
        };
        let impl_use_len = if off + tag_size + 20 <= data.len() {
            u16::from_le_bytes([data[off + tag_size + 18], data[off + tag_size + 19]]) as usize
        } else {
            off += fid_advance.max(4);
            continue;
        };

        if file_chars & FC_PARENT == 0 {
            let is_dir = file_chars & FC_DIRECTORY != 0;
            let fe_lba = partition_start + icb_lbn;

            let id_start = off + tag_size + 20 + impl_use_len;
            let id_end = (id_start + file_id_len).min(data.len());
            let name = if id_end > id_start {
                decode_osta_cs0(&data[id_start..id_end])
            } else {
                String::new()
            };

            // Read the FE to get the canonical file size.
            let size = read_fe_info_len(reader, block_size, fe_lba).unwrap_or(0);

            entries.push(UdfFileEntry {
                name,
                is_dir,
                size,
                fe_lba,
            });
        }

        off += fid_advance.max(4);
    }
    entries
}

/// Read the Information Length (file size) from a File Entry at `fe_lba`.
fn read_fe_info_len<R: Read + Seek>(reader: &mut R, block_size: u32, fe_lba: u32) -> Option<u64> {
    let mut sector = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut sector[..block_size as usize];
    seek_read(reader, fe_lba as u64 * block_size as u64, sector)?;
    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && tag_ident != TAG_EFE {
        return None;
    }
    Some(u64::from_le_bytes(sector[56..64].try_into().unwrap()))
}

/// Collect data from short allocation descriptors (8 bytes each).
fn read_extents_short<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    ad_area: &[u8],
    total_len: u64,
) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut pos = 0;
    while pos + 8 <= ad_area.len() && (data.len() as u64) < total_len {
        let len_raw = u32::from_le_bytes(ad_area[pos..pos + 4].try_into().unwrap());
        let ext_pos = u32::from_le_bytes(ad_area[pos + 4..pos + 8].try_into().unwrap());
        let ext_type = len_raw >> 30;
        let ext_len = (len_raw & 0x3FFF_FFFF) as usize;
        if ext_type == (EXTENT_RECORDED >> 30) && ext_len > 0 {
            let phys = (partition_start as u64 + ext_pos as u64) * block_size as u64;
            read_extent(reader, block_size, phys, ext_len, total_len, &mut data)?;
        }
        pos += 8;
    }
    data.truncate(total_len as usize);
    Some(data)
}

/// Collect data from long allocation descriptors (16 bytes each).
fn read_extents_long<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    ad_area: &[u8],
    total_len: u64,
) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut pos = 0;
    while pos + 16 <= ad_area.len() && (data.len() as u64) < total_len {
        let len_raw = u32::from_le_bytes(ad_area[pos..pos + 4].try_into().unwrap());
        let lbn = u32::from_le_bytes(ad_area[pos + 4..pos + 8].try_into().unwrap());
        let ext_type = len_raw >> 30;
        let ext_len = (len_raw & 0x3FFF_FFFF) as usize;
        if ext_type == (EXTENT_RECORDED >> 30) && ext_len > 0 {
            let phys = (partition_start as u64 + lbn as u64) * block_size as u64;
            read_extent(reader, block_size, phys, ext_len, total_len, &mut data)?;
        }
        pos += 16;
    }
    data.truncate(total_len as usize);
    Some(data)
}

/// Read `ext_len` bytes from `byte_pos`, appending to `data` up to `total_len`.
fn read_extent<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    byte_pos: u64,
    ext_len: usize,
    total_len: u64,
    data: &mut Vec<u8>,
) -> Option<()> {
    let bs = block_size as usize;
    let sectors = ext_len.div_ceil(bs);
    for i in 0..sectors {
        let mut sector = [0u8; MAX_BLOCK_SIZE];
        let sector = &mut sector[..bs];
        seek_read(reader, byte_pos + i as u64 * block_size as u64, sector)?;
        let already = data.len() as u64;
        let remaining = total_len.saturating_sub(already) as usize;
        let sector_bytes = (ext_len - i * bs).min(bs);
        let take = sector_bytes.min(remaining);
        data.extend_from_slice(&sector[..take]);
    }
    Some(())
}

/// Decode an OSTA CS0 encoded identifier: first byte is compression ID
/// (8 = UTF-8, 16 = UTF-16BE), remainder is character data.
fn decode_osta_cs0(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let comp_id = bytes[0];
    let payload = &bytes[1..];
    match comp_id {
        8 => String::from_utf8_lossy(payload).into_owned(),
        16 => {
            let pairs: Vec<u16> = payload
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&pairs)
        }
        _ => String::from_utf8_lossy(payload).into_owned(),
    }
}

/// Seek to `byte_pos` and read exactly `buf.len()` bytes; returns `None` on any error.
fn seek_read<R: Read + Seek>(reader: &mut R, byte_pos: u64, buf: &mut [u8]) -> Option<()> {
    seek_read_checked(reader, byte_pos, buf).ok()
}

/// Seek to `byte_pos` and read exactly `buf.len()` bytes, propagating the real
/// [`io::Error`] (a truncated image yields [`io::ErrorKind::UnexpectedEof`]).
fn seek_read_checked<R: Read + Seek>(
    reader: &mut R,
    byte_pos: u64,
    buf: &mut [u8],
) -> Result<(), io::Error> {
    reader.seek(SeekFrom::Start(byte_pos))?;
    reader.read_exact(buf)?;
    Ok(())
}

// ── Forensic-findings support (used by `findings`) ───────────────────────────

/// The ECMA-167 descriptor-tag checksum (3/7.2): the mod-256 sum of the 16 tag
/// bytes excluding byte 4 (the checksum field itself).
pub(crate) fn tag_checksum(tag: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &b) in tag.iter().take(16).enumerate() {
        if i == 4 {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b));
    }
    (sum & 0xFF) as u8
}

/// The ECMA-167 descriptor CRC (3/7.2): CRC-CCITT with polynomial `0x1021`,
/// initial value `0x0000`, no input/output reflection and no final XOR,
/// computed over the descriptor body (the bytes after the 16-byte tag).
pub(crate) fn ecma167_crc(body: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in body {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Human-readable label for a descriptor tag identifier, or `None` for an
/// identifier this crate does not recognise (so the caller does not validate a
/// non-descriptor sector).
pub(crate) fn descriptor_label(tag_ident: u16) -> Option<&'static str> {
    Some(match tag_ident {
        TAG_AVDP => "AVDP",
        TAG_PD => "PartitionDescriptor",
        TAG_LVD => "LogicalVolumeDescriptor",
        TAG_TERM => "TerminatingDescriptor",
        TAG_FSD => "FileSetDescriptor",
        TAG_FID => "FileIdentifierDescriptor",
        TAG_FE | TAG_FE_ALT => "FileEntry",
        TAG_EFE => "ExtendedFileEntry",
        1 => "PrimaryVolumeDescriptor",
        3 => "VolumeDescriptorPointer",
        4 => "ImplementationUseVolumeDescriptor",
        7 => "UnallocatedSpaceDescriptor",
        9 => "LogicalVolumeIntegrityDescriptor",
        258 => "AllocationExtentDescriptor",
        259 => "IndirectEntry",
        262 => "SpaceBitmapDescriptor",
        263 => "PartitionIntegrityEntry",
        264 => "ExtendedAttributeHeaderDescriptor",
        265 => "UnallocatedSpaceEntry",
        _ => return None,
    })
}

/// Decode an ECMA-167 `timestamp` (1/7.3, 12 bytes) to `YYYY-MM-DD HH:MM:SS`,
/// or `None` when the year is implausible (0 / out of the 1970..=2200 range),
/// which marks an unset or non-timestamp field rather than a real time.
pub(crate) fn decode_timestamp(b: &[u8]) -> Option<String> {
    if b.len() < 12 {
        return None;
    }
    let year = i16::from_le_bytes([b[2], b[3]]);
    if !(1970..=2200).contains(&year) {
        return None;
    }
    let (month, day, hour, minute, second) = (b[4], b[5], b[6], b[7], b[8]);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
    ))
}

/// Read the File Set Descriptor's recording time (4/14.1, offset 16) from the
/// FSD at `fsd_lba`. `Ok(None)` when the sector is not an FSD or the time is
/// unset.
pub(crate) fn fsd_recording_time<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    fsd_lba: u32,
) -> Result<Option<String>, io::Error> {
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut buf[..block_size as usize];
    seek_read_checked(reader, u64::from(fsd_lba) * u64::from(block_size), sector)?;
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_FSD {
        return Ok(None);
    }
    Ok(decode_timestamp(&sector[16..28]))
}

/// The Modification Time of a File Entry sector (`is_efe` selects the Extended
/// File Entry layout, whose extra Object Size + Creation Time fields shift the
/// timestamps): base FE modification time is at offset 84, EFE at offset 92.
pub(crate) fn fe_modification_time(sector: &[u8], is_efe: bool) -> Option<String> {
    let off = if is_efe { 92 } else { 84 };
    decode_timestamp(sector.get(off..off + 12)?)
}

/// Count the non-zero bytes in a File Entry's final-block slack — the unused
/// tail of the last logical block after `InformationLength`, since a file
/// occupies whole logical blocks.
///
/// Returns `(nonzero_bytes, slack_bytes)`, or `None` when the file has no
/// trailing slack (size is a whole-block multiple), is zero-length, has its data
/// stored inline in the File Entry (no allocated block to hold slack), or its
/// final block cannot be located/read.
pub(crate) fn fe_slack_nonzero<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    fe_lba: u32,
) -> Option<(u32, u32)> {
    let info_len = read_fe_info_len(reader, block_size, fe_lba)?;
    let bs = u64::from(block_size);
    let slack = (bs - info_len % bs) % bs;
    if info_len == 0 || slack == 0 {
        return None;
    }
    // Physical byte position of the file's last allocated block, walked through
    // the FE's allocation descriptors so the slack inspected is the true final
    // block (not a guess). Inline-stored files have no allocated block and so no
    // slack to inspect.
    let last_block_pos = fe_last_block_pos(reader, block_size, partition_start, fe_lba)?;
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    let block = &mut buf[..block_size as usize];
    seek_read_checked(reader, last_block_pos, block).ok()?;

    let slack_start = (info_len % bs) as usize;
    let nonzero = block[slack_start..].iter().filter(|&&b| b != 0).count() as u32;
    Some((nonzero, slack as u32))
}

/// Physical byte position of the *last* logical block holding a File Entry's
/// data, resolved by walking its allocation descriptors. `None` for inline
/// (in-ICB) data, an unreadable FE, or an FE with no recorded extent.
fn fe_last_block_pos<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    partition_start: u32,
    fe_lba: u32,
) -> Option<u64> {
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut buf[..block_size as usize];
    seek_read_checked(reader, u64::from(fe_lba) * u64::from(block_size), sector).ok()?;

    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    let is_efe = tag_ident == TAG_EFE;
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && !is_efe {
        return None;
    }

    let icb_flags = u16::from_le_bytes([sector[34], sector[35]]);
    let alloc_type = icb_flags & 0x0007;
    let (ea_off, ad_off, header) = if is_efe {
        (176usize, 180usize, 184usize)
    } else {
        (168usize, 172usize, 176usize)
    };
    if ad_off + 4 > sector.len() {
        return None; // cov:unreachable: header offsets fit a >=512-byte block
    }
    let ea_len = u32::from_le_bytes(sector[ea_off..ea_off + 4].try_into().ok()?) as usize;
    let ad_len = u32::from_le_bytes(sector[ad_off..ad_off + 4].try_into().ok()?) as usize;
    let ad_start = header + ea_len;
    let ad_end = ad_start.checked_add(ad_len)?;
    if ad_end > sector.len() {
        return None;
    }
    let ad_area = &sector[ad_start..ad_end];

    // Both short_ad (8 bytes) and long_ad (16 bytes) record the extent length at
    // bytes 0..4 and the logical block number at bytes 4..8; only the stride to
    // the next descriptor differs. Inline (in-ICB) data has no allocated block.
    let stride = match alloc_type {
        ALLOC_SHORT => 8,
        ALLOC_LONG => 16,
        _ => return None,
    };
    let mut last: Option<u64> = None;
    let mut pos = 0;
    while pos + stride <= ad_area.len() {
        let len_raw = read_le_u32(ad_area, pos);
        let ext_type = len_raw >> 30;
        let ext_len = (len_raw & 0x3FFF_FFFF) as usize;
        if ext_type == (EXTENT_RECORDED >> 30) && ext_len > 0 {
            let lbn = read_le_u32(ad_area, pos + 4);
            let blocks_in_ext = ext_len.div_ceil(block_size as usize) as u64;
            let last_lbn = u64::from(partition_start) + u64::from(lbn) + (blocks_in_ext - 1);
            last = Some(last_lbn * u64::from(block_size));
        }
        pos += stride;
    }
    last
}

/// Read a little-endian `u32` at `off`, returning 0 if out of range (the caller
/// has already bounds-checked the slice length, so the fallback is defensive).
fn read_le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod real_media_tests {
    //! Validate partition-map classification against real mkudffs-authored
    //! pure-UDF images, cross-checked against the independent `udfinfo`
    //! (udftools) oracle. The images and the verbatim `mkudffs` commands that
    //! produced them are documented in `tests/data/README.md`; they are
    //! committed, so these tests run (the skip-if-missing arm is a defensive
    //! fallback for a checkout where the fixtures were stripped).
    use super::{parse_udf_state, UdfPartitionKind};
    use std::fs::File;

    fn state(name: &str) -> Option<super::UdfState> {
        let path = format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name);
        let mut f = File::open(&path).ok()?;
        parse_udf_state(&mut f)
    }

    #[test]
    fn vat_image_classified_virtual() {
        let Some(st) = state("udf_vat.img") else {
            eprintln!("skip: udf_vat.img");
            return;
        };
        assert_eq!(
            st.partition_kind,
            UdfPartitionKind::Virtual,
            "mkudffs cdr/1.50 image must classify as Virtual (VAT)"
        );
    }

    #[test]
    fn sparable_image_classified_sparable() {
        let Some(st) = state("udf_spar.img") else {
            eprintln!("skip: udf_spar.img");
            return;
        };
        assert_eq!(
            st.partition_kind,
            UdfPartitionKind::Sparable,
            "mkudffs dvdrw/2.01 image must classify as Sparable"
        );
    }

    /// Differential reconciliation against the independent `udfinfo` oracle
    /// (udftools 2.3, a separate codebase from this crate). The expected values
    /// below are the *oracle's* reported ground truth — partition-space start
    /// and partition-map shape derived from `udfinfo`'s output, NOT recomputed
    /// by this crate. See `tests/data/README.md` for the captured oracle output.
    ///
    /// `udfinfo udf_vat.img` reports `udfrev=1.50`, `accesstype=writeonce`, and
    /// `start=257, blocks=3839, type=PSPACE`; the cdr/1.50 layout carries a
    /// physical map plus a Type-2 `*UDF Virtual Partition` map (VAT), so the
    /// file-set partition resolves to physical start 257 and two partition maps.
    #[test]
    fn vat_image_matches_udfinfo_oracle() {
        let Some(st) = state("udf_vat.img") else {
            eprintln!("skip: udf_vat.img");
            return;
        };
        assert_eq!(st.partition_kind, UdfPartitionKind::Virtual);
        // udfinfo PSPACE start block.
        assert_eq!(
            st.partition_start, 257,
            "partition start must match udfinfo PSPACE start=257"
        );
        // Physical + Virtual (VAT) Type-2 map.
        assert_eq!(
            st.partition_map_count, 2,
            "cdr/1.50 carries a physical map plus the VAT Type-2 map"
        );
    }

    /// `udfinfo udf_spar.img` reports `udfrev=2.01`, `accesstype=overwritable`,
    /// a `type=SSPACE` (sparing) region, and `start=1296, blocks=2528,
    /// type=PSPACE`; the dvdrw/2.01 layout uses a single Type-2 `*UDF Sparable
    /// Partition` map, so the file-set partition resolves to physical start 1296
    /// with one partition map.
    #[test]
    fn sparable_image_matches_udfinfo_oracle() {
        let Some(st) = state("udf_spar.img") else {
            eprintln!("skip: udf_spar.img");
            return;
        };
        assert_eq!(st.partition_kind, UdfPartitionKind::Sparable);
        // udfinfo PSPACE start block.
        assert_eq!(
            st.partition_start, 1296,
            "partition start must match udfinfo PSPACE start=1296"
        );
        assert_eq!(
            st.partition_map_count, 1,
            "dvdrw/2.01 carries a single Sparable Type-2 map"
        );
    }

    /// `udfinfo udf_plain.img` reports `udfrev=2.01`, `blocksize=512`, and a
    /// single physical partition at `start=257, type=PSPACE`. The mkudffs `hd`
    /// profile writes 512-byte logical blocks, so the AVDP lives at byte
    /// 256×512, not 256×2048 — this image only parses once the block size is
    /// detected from the medium rather than assumed to be 2048.
    #[test]
    fn plain_512_block_image_parses_via_detected_block_size() {
        let path = format!("{}/tests/data/udf_plain.img", env!("CARGO_MANIFEST_DIR"));
        let mut f = File::open(&path).expect("udf_plain.img fixture must be present");
        let st = super::parse_udf_state(&mut f)
            .expect("512-byte-block UDF must parse once the block size is detected from the AVDP");
        assert_eq!(st.block_size, 512, "udfinfo reports blocksize=512");
        assert_eq!(
            st.partition_kind,
            UdfPartitionKind::Physical,
            "mkudffs hd image is a Type-1 physical partition"
        );
        assert_eq!(
            st.partition_start, 257,
            "partition start must match udfinfo PSPACE start=257"
        );
        assert_eq!(
            st.partition_map_count, 1,
            "hd/2.01 carries a single physical map"
        );
    }
}

#[cfg(test)]
mod checked_bootstrap_tests {
    //! `parse_udf_state_checked` must distinguish a real seek/read I/O failure
    //! (a bootstrap read failure — truncated/unreadable image) from a structural
    //! negative (reads succeeded but the anchor is not a valid AVDP → not UDF).
    use super::parse_udf_state_checked;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    /// A `Read + Seek` whose seeks always succeed but whose reads always fail
    /// with a non-EOF I/O error — models an unreadable image / device fault.
    struct FaultyReader;

    impl Read for FaultyReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("device read fault"))
        }
    }
    impl Seek for FaultyReader {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn io_error_at_anchor_surfaces_as_err() {
        let mut r = FaultyReader;
        let res = parse_udf_state_checked(&mut r);
        assert!(
            res.is_err(),
            "a device read fault reading the anchor must surface as Err, not Ok(None)"
        );
    }

    #[test]
    fn truncated_before_anchor_surfaces_as_err() {
        // A buffer too short to reach LBA 256 (256 * 2048 = 524288 bytes) — the
        // read_exact at the anchor hits UnexpectedEof, which is a truncated-image
        // bootstrap failure and must surface, not be swallowed into Ok(None).
        let buf = vec![0u8; 4096];
        let mut r = Cursor::new(buf);
        let res = parse_udf_state_checked(&mut r);
        assert!(
            res.is_err(),
            "truncation before the AVDP anchor must surface as Err (UnexpectedEof)"
        );
        let err = res.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn full_size_but_wrong_anchor_is_ok_none() {
        // A buffer large enough to reach and read LBA 256, but whose sector 256 is
        // all zeros (tag identifier 0, not TAG_AVDP=2) — reads succeed, the
        // structure is simply not UDF. This is the legitimate "not UDF" case.
        let buf = vec![0u8; 257 * 2048];
        let mut r = Cursor::new(buf);
        let res = parse_udf_state_checked(&mut r);
        assert!(
            matches!(res, Ok(None)),
            "a readable image with a non-AVDP anchor must be Ok(None), got {res:?}"
        );
    }
}

#[cfg(test)]
mod findings_support_tests {
    //! Unit coverage for the findings-support primitives. The CRC/checksum
    //! implementations are additionally validated against the real `mkudffs`
    //! corpus by the `findings` integration tests (a clean image's descriptors
    //! must all verify — a true negative); these tests cover the pure helpers
    //! and the allocated-extent slack path the inline-data corpus cannot reach.
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc_ccitt_matches_known_vectors() {
        // CRC-CCITT (poly 0x1021, init 0x0000): "123456789" → 0x31C3 is the
        // standard published vector for this parameterisation.
        assert_eq!(ecma167_crc(b"123456789"), 0x31C3);
        assert_eq!(ecma167_crc(&[]), 0x0000);
    }

    #[test]
    fn tag_checksum_skips_byte_4() {
        let mut tag = [0u8; 16];
        tag[0] = 2; // contributes
        tag[4] = 0xFF; // the checksum byte itself — must be excluded
        tag[6] = 3; // contributes
        assert_eq!(tag_checksum(&tag), 5);
    }

    #[test]
    fn descriptor_label_known_and_unknown() {
        // Every mapped ECMA-167 / UDF descriptor identifier resolves to a name
        // so a walked descriptor of any type is reported by name, not a number.
        for (id, name) in [
            (TAG_FSD, "FileSetDescriptor"),
            (TAG_EFE, "ExtendedFileEntry"),
            (TAG_FID, "FileIdentifierDescriptor"),
            (TAG_FE, "FileEntry"),
            (TAG_FE_ALT, "FileEntry"),
            (1, "PrimaryVolumeDescriptor"),
            (3, "VolumeDescriptorPointer"),
            (4, "ImplementationUseVolumeDescriptor"),
            (7, "UnallocatedSpaceDescriptor"),
            (9, "LogicalVolumeIntegrityDescriptor"),
            (258, "AllocationExtentDescriptor"),
            (259, "IndirectEntry"),
            (262, "SpaceBitmapDescriptor"),
            (263, "PartitionIntegrityEntry"),
            (264, "ExtendedAttributeHeaderDescriptor"),
            (265, "UnallocatedSpaceEntry"),
        ] {
            assert_eq!(descriptor_label(id), Some(name), "tag {id}");
        }
        assert_eq!(descriptor_label(0xFFFF), None);
    }

    #[test]
    fn fsd_recording_time_none_for_non_fsd() {
        let img = vec![0u8; 512];
        let mut r = Cursor::new(img);
        assert_eq!(fsd_recording_time(&mut r, 512, 0).unwrap(), None);
    }

    #[test]
    fn last_block_pos_none_for_non_file_entry() {
        let img = vec![0u8; 512];
        let mut r = Cursor::new(img);
        assert_eq!(fe_last_block_pos(&mut r, 512, 0, 0), None);
    }

    #[test]
    fn slack_via_long_allocation_descriptor() {
        // A 16-byte long_ad (alloc type 1) exercises the ALLOC_LONG stride.
        let bs = 512usize;
        let mut img = vec![0u8; bs * 8];
        let fe = 4 * bs;
        img[fe..fe + 2].copy_from_slice(&TAG_FE.to_le_bytes());
        img[fe + 34..fe + 36].copy_from_slice(&1u16.to_le_bytes()); // long_ad alloc
        img[fe + 56..fe + 64].copy_from_slice(&100u64.to_le_bytes());
        img[fe + 168..fe + 172].copy_from_slice(&0u32.to_le_bytes()); // L_EA
        img[fe + 172..fe + 176].copy_from_slice(&16u32.to_le_bytes()); // L_AD = one long_ad
        img[fe + 176..fe + 180].copy_from_slice(&100u32.to_le_bytes()); // extent_length
        img[fe + 180..fe + 184].copy_from_slice(&5u32.to_le_bytes()); // logical block num
        let data = 5 * bs + 100;
        img[data] = 0x7F;
        let mut r = Cursor::new(img);
        let (nonzero, slack) = fe_slack_nonzero(&mut r, 512, 0, 4).expect("slack present");
        assert_eq!(slack, 412);
        assert_eq!(nonzero, 1);
    }

    #[test]
    fn timestamp_decodes_and_rejects_implausible() {
        let mut t = [0u8; 12];
        t[2..4].copy_from_slice(&2026i16.to_le_bytes());
        t[4] = 6; // month
        t[5] = 21; // day
        t[6] = 8; // hour
        t[7] = 46; // minute
        t[8] = 57; // second
        assert_eq!(decode_timestamp(&t).as_deref(), Some("2026-06-21 08:46:57"));

        // Year out of range → None (unset/garbage field).
        let mut bad = t;
        bad[2..4].copy_from_slice(&0i16.to_le_bytes());
        assert_eq!(decode_timestamp(&bad), None);

        // Month out of range → None.
        let mut badmon = t;
        badmon[4] = 0;
        assert_eq!(decode_timestamp(&badmon), None);

        // Short buffer → None.
        assert_eq!(decode_timestamp(&[0u8; 4]), None);
    }

    #[test]
    fn fe_modification_time_offset_differs_for_efe() {
        // Base FE: mtime at offset 84; EFE: mtime at offset 92.
        let mut fe = vec![0u8; 512];
        let stamp = |buf: &mut [u8], off: usize, year: i16| {
            buf[off + 2..off + 4].copy_from_slice(&year.to_le_bytes());
            buf[off + 4] = 1; // month
            buf[off + 5] = 1; // day
        };
        stamp(&mut fe, 84, 2030);
        assert_eq!(
            fe_modification_time(&fe, false).as_deref(),
            Some("2030-01-01 00:00:00")
        );
        let mut efe = vec![0u8; 512];
        stamp(&mut efe, 92, 2031);
        assert_eq!(
            fe_modification_time(&efe, true).as_deref(),
            Some("2031-01-01 00:00:00")
        );
    }

    /// Build a minimal 512-byte-block image with a base File Entry that points,
    /// via a short allocation descriptor, to a single data block whose tail
    /// (past `InformationLength`) holds non-zero slack — the allocated-extent
    /// path the inline-data `mkudffs` corpus cannot exercise.
    fn image_with_slack(info_len: u64, slack_fill: &[u8]) -> (Vec<u8>, u32, u32) {
        let bs = 512usize;
        let part_start = 0u32;
        let fe_lba = 4u32;
        let data_lbn = 5u32; // physical = part_start + 5
        let mut img = vec![0u8; bs * 8];

        let fe = fe_lba as usize * bs;
        // Tag identifier = File Entry (260).
        img[fe..fe + 2].copy_from_slice(&TAG_FE.to_le_bytes());
        // ICB flags: allocation type 0 (short_ad).
        img[fe + 34..fe + 36].copy_from_slice(&0u16.to_le_bytes());
        // InformationLength.
        img[fe + 56..fe + 64].copy_from_slice(&info_len.to_le_bytes());
        // Base-FE header offsets: L_EA @168, L_AD @172, AD area @176.
        img[fe + 168..fe + 172].copy_from_slice(&0u32.to_le_bytes()); // L_EA = 0
        img[fe + 172..fe + 176].copy_from_slice(&8u32.to_le_bytes()); // L_AD = 8 (one short_ad)
                                                                      // short_ad: extent_length (recorded, type 0) = info_len, position = data_lbn.
        let ad = fe + 176;
        img[ad..ad + 4].copy_from_slice(&(info_len as u32).to_le_bytes());
        img[ad + 4..ad + 8].copy_from_slice(&data_lbn.to_le_bytes());

        // Data block: fill the slack region (past info_len within the block).
        let data = (part_start + data_lbn) as usize * bs;
        let slack_start = data + (info_len as usize % bs);
        for (i, &b) in slack_fill.iter().enumerate() {
            img[slack_start + i] = b;
        }
        (img, part_start, fe_lba)
    }

    #[test]
    fn slack_counts_nonzero_tail_bytes() {
        // info_len 100 in a 512-byte block → 412 slack bytes; place 3 non-zero.
        let (img, ps, fe) = image_with_slack(100, &[0xAA, 0x00, 0xBB, 0xCC]);
        let mut r = Cursor::new(img);
        let (nonzero, slack) = fe_slack_nonzero(&mut r, 512, ps, fe).expect("slack present");
        assert_eq!(slack, 412);
        assert_eq!(nonzero, 3);
    }

    #[test]
    fn slack_none_when_block_aligned() {
        // info_len exactly one block → no slack.
        let (img, ps, fe) = image_with_slack(512, &[0xFF]);
        let mut r = Cursor::new(img);
        assert_eq!(fe_slack_nonzero(&mut r, 512, ps, fe), None);
    }

    #[test]
    fn slack_none_when_zero_length() {
        let (img, ps, fe) = image_with_slack(0, &[]);
        let mut r = Cursor::new(img);
        assert_eq!(fe_slack_nonzero(&mut r, 512, ps, fe), None);
    }

    #[test]
    fn slack_none_for_inline_data() {
        // Allocation type 3 (inline) has no allocated block to inspect.
        let (mut img, ps, fe) = image_with_slack(100, &[0xAA]);
        let fe_off = fe as usize * 512;
        img[fe_off + 34..fe_off + 36].copy_from_slice(&3u16.to_le_bytes());
        let mut r = Cursor::new(img);
        assert_eq!(fe_slack_nonzero(&mut r, 512, ps, fe), None);
    }
}
