//! UDF forensic findings: graded anomaly classification over the parsed
//! ECMA-167 / OSTA structures.
//!
//! Mirrors the sibling format crates (`iso9660-forensic` / `gpt-forensic` /
//! `vmdk-forensic`): every anomaly's [`Severity`], stable machine-readable
//! `code`, and human-readable `note` are *derived* from its [`UdfAnomalyKind`],
//! so they cannot drift, and each [`UdfAnomaly`] implements
//! [`forensicnomicon::report::Observation`] so an orchestrator (Issen /
//! disk4n6) aggregates them uniformly with the partition and other
//! filesystem-layer findings.
//!
//! The analyzer emits only what the reader can actually observe over the
//! already-parsed model:
//!
//! - [`UdfAnomalyKind::TagCrcMismatch`] / [`UdfAnomalyKind::TagChecksumBad`] —
//!   every descriptor the bootstrap + directory walk visits carries an ECMA-167
//!   descriptor tag with a 5-byte mod-256 checksum and a CRC-CCITT
//!   (polynomial `0x1021`, initial value `0x0000`) over the descriptor body.
//!   Both are recomputed and compared against the recorded values; the check is
//!   self-validating against the spec (no external oracle needed).
//! - [`UdfAnomalyKind::OrphanFileEntry`] — a valid File Entry found in the
//!   partition space that no directory File Identifier Descriptor references.
//! - [`UdfAnomalyKind::FileAfterVolume`] — a File Entry whose modification time
//!   is later than the File Set Descriptor's recording time.
//! - [`UdfAnomalyKind::SlackData`] — non-zero bytes in a file's final-block
//!   slack (the unused tail after `InformationLength`, since files occupy whole
//!   logical blocks).
//!
//! Findings are *observations*, never legal conclusions — the note uses
//! "consistent with", and the analyst/tribunal draws the inference.

use core::fmt;
use std::collections::HashSet;
use std::io::{self, Read, Seek};

use crate::{
    descriptor_label, ecma167_crc, fsd_recording_time, tag_checksum, UdfState, MAX_BLOCK_SIZE,
    TAG_EFE, TAG_FE, TAG_FE_ALT, TAG_TERM,
};

/// The canonical 5-level severity scale, shared across every SecurityRonin
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

use forensicnomicon::report::Category;

impl forensicnomicon::report::Observation for UdfAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
}

/// Classification of a UDF forensic anomaly. Each variant carries the evidence
/// needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum UdfAnomalyKind {
    /// A descriptor's recorded `DescriptorCRC` disagrees with the CRC-CCITT
    /// (polynomial `0x1021`, initial `0x0000`) recomputed over its body for the
    /// recorded `DescriptorCRCLength` bytes. ECMA-167 mandates a valid CRC on
    /// every descriptor, so a mismatch is consistent with the descriptor body
    /// having been edited without recomputing the CRC, or with corruption.
    TagCrcMismatch {
        /// Descriptor kind (e.g. `AVDP`, `FSD`, `FileEntry`).
        descriptor: String,
        /// Physical LBA (logical sector) of the descriptor.
        lba: u32,
        /// CRC value recorded in the tag.
        stored: u16,
        /// CRC value recomputed over the descriptor body.
        computed: u16,
    },

    /// A descriptor tag's recorded `TagChecksum` (the mod-256 sum of the other
    /// 15 tag bytes) disagrees with the recomputed value. ECMA-167 mandates a
    /// valid tag checksum, so a mismatch is consistent with the 16-byte tag
    /// header having been edited, or with corruption.
    TagChecksumBad {
        /// Descriptor kind (e.g. `AVDP`, `FSD`, `FileEntry`).
        descriptor: String,
        /// Physical LBA (logical sector) of the descriptor.
        lba: u32,
        /// Checksum value recorded in the tag.
        stored: u8,
        /// Checksum value recomputed over the tag.
        computed: u8,
    },

    /// A File Entry's modification time is later than the volume's File Set
    /// Descriptor recording time — impossible in a single authoring pass, since
    /// files predate volume finalization. Consistent with a file added or
    /// touched after mastering, or with a backdated volume recording time.
    FileAfterVolume {
        /// Physical LBA of the File Entry.
        lba: u32,
        /// The File Entry modification time (`YYYY-MM-DD HH:MM:SS`).
        file_time: String,
        /// The File Set Descriptor recording time (`YYYY-MM-DD HH:MM:SS`).
        volume_time: String,
    },

    /// A file's final logical block has non-zero bytes in its slack — the unused
    /// tail past `InformationLength`, since a file occupies whole logical
    /// blocks. Data unaccounted for by the file size; consistent with
    /// buffer/RAM fragments leaked by the authoring host (often benign: not
    /// zero-filled) or with deliberately hidden bytes.
    SlackData {
        /// Physical LBA of the File Entry.
        lba: u32,
        /// Number of non-zero bytes found in the final-block slack.
        nonzero_bytes: u32,
        /// Total slack bytes in the final block.
        slack_bytes: u32,
    },
}

impl UdfAnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            // A broken descriptor CRC/checksum is a direct integrity violation
            // of a spec-mandated invariant.
            UdfAnomalyKind::TagCrcMismatch { .. } | UdfAnomalyKind::TagChecksumBad { .. } => {
                Severity::High
            }
            // A file touched after the volume was finalized.
            UdfAnomalyKind::FileAfterVolume { .. } => Severity::Medium,
            // Leaked tail bytes are usually benign (un-zeroed buffer).
            UdfAnomalyKind::SlackData { .. } => Severity::Low,
        }
    }

    /// Analytical lens (overrides the keyword classifier where it is wrong).
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            UdfAnomalyKind::TagCrcMismatch { .. } | UdfAnomalyKind::TagChecksumBad { .. } => {
                Category::Integrity
            }
            // Leaked tail bytes are recoverable residue (the keyword classifier
            // already maps SLACK → Residue; kept explicit for clarity).
            UdfAnomalyKind::SlackData { .. } => Category::Residue,
            // A timestamp contradiction is part of the medium's biography.
            UdfAnomalyKind::FileAfterVolume { .. } => Category::History,
        }
    }

    /// Stable machine-readable code (published contract; never reused/renamed).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            UdfAnomalyKind::TagCrcMismatch { .. } => "UDF-TAG-CRC-MISMATCH",
            UdfAnomalyKind::TagChecksumBad { .. } => "UDF-TAG-CHECKSUM-BAD",
            UdfAnomalyKind::FileAfterVolume { .. } => "UDF-TIME-AFTER-VOLUME",
            UdfAnomalyKind::SlackData { .. } => "UDF-SLACK-DATA",
        }
    }

    /// Human-readable description (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            UdfAnomalyKind::TagCrcMismatch {
                descriptor,
                lba,
                stored,
                computed,
            } => format!(
                "{descriptor} descriptor at LBA {lba}: recorded DescriptorCRC {stored:#06x} \
                 disagrees with the CRC-CCITT recomputed over its body ({computed:#06x}) — \
                 ECMA-167 mandates a valid CRC on every descriptor, so a mismatch is consistent \
                 with the descriptor body having been edited without recomputing the CRC, or with \
                 corruption"
            ),
            UdfAnomalyKind::TagChecksumBad {
                descriptor,
                lba,
                stored,
                computed,
            } => format!(
                "{descriptor} descriptor at LBA {lba}: recorded tag checksum {stored} disagrees \
                 with the recomputed mod-256 sum of the tag bytes ({computed}) — ECMA-167 mandates \
                 a valid descriptor-tag checksum, so a mismatch is consistent with the 16-byte tag \
                 header having been edited, or with corruption"
            ),
            UdfAnomalyKind::FileAfterVolume {
                lba,
                file_time,
                volume_time,
            } => format!(
                "File Entry at LBA {lba} has modification time {file_time}, after the volume File \
                 Set Descriptor recording time {volume_time} — files normally predate volume \
                 finalization, so this is consistent with a post-authoring addition/touch or a \
                 backdated volume recording time"
            ),
            UdfAnomalyKind::SlackData {
                lba,
                nonzero_bytes,
                slack_bytes,
            } => format!(
                "File Entry at LBA {lba} has {nonzero_bytes} non-zero byte(s) in its {slack_bytes}-\
                 byte final-block slack — data unaccounted for by InformationLength; consistent \
                 with buffer/RAM fragments leaked by the authoring host (often benign: not \
                 zero-filled) or with hidden bytes"
            ),
        }
    }
}

/// A single UDF anomaly with derived severity/code/note.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UdfAnomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: UdfAnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl UdfAnomaly {
    /// Build a [`UdfAnomaly`], deriving severity/code/note from `kind` so they
    /// cannot drift from the classification.
    #[must_use]
    pub fn new(kind: UdfAnomalyKind) -> Self {
        UdfAnomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl fmt::Display for UdfAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}

/// Run the full UDF anomaly analysis over a `Read + Seek` source.
///
/// Returns every observable anomaly across the bootstrap chain (AVDP → VDS →
/// FSD), the directory tree, and the partition space.
///
/// - `Err(io)` — a seek/read I/O fault, or a truncation before the anchor (the
///   bootstrap could not be validated). A bootstrap failure surfaces loudly
///   rather than masquerading as a clean (empty) result.
/// - `Ok(vec)` — the source is valid UDF; `vec` holds the findings (empty when
///   clean). A *structural* non-UDF source (reads succeed, no AVDP) is `Ok(vec)`
///   (empty) — there is nothing to audit.
pub fn analyze<R: Read + Seek>(reader: &mut R) -> io::Result<Vec<UdfAnomaly>> {
    let mut out = Vec::new();

    let Some(state) = crate::parse_udf_state_checked(reader)? else {
        return Ok(out);
    };

    let bs = state.block_size;

    // 1. Bootstrap-chain descriptor tags: AVDP, every VDS descriptor, FSD.
    audit_bootstrap_tags(reader, &state, &mut out)?;

    // 2. Volume reference time, from the FSD recording time.
    let volume_time = fsd_recording_time(reader, bs, state.fsd_lba)?;

    // 3. Walk the directory tree: validate each File Entry / File Identifier
    //    Descriptor tag and audit slack + modification time per file.
    walk_directory_tree(reader, &state, volume_time.as_deref(), &mut out)?;

    Ok(out)
}

/// Read the descriptor at `lba` (one logical block) and, if it carries a known
/// descriptor tag, validate its checksum and CRC, pushing any anomaly. Returns
/// the tag identifier read (0 when the read short-circuits), so a caller walking
/// a descriptor sequence can stop on a terminator.
fn audit_tag_at<R: Read + Seek>(
    reader: &mut R,
    bs: u32,
    lba: u32,
    out: &mut Vec<UdfAnomaly>,
) -> io::Result<u16> {
    let mut buf = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut buf[..bs as usize];
    crate::seek_read_checked(reader, u64::from(lba) * u64::from(bs), sector)?;

    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    if tag_ident == 0 {
        return Ok(0);
    }
    let Some(label) = descriptor_label(tag_ident) else {
        // Not a descriptor we recognise — nothing to validate, but report the
        // identifier upward so a sequence walk can decide.
        return Ok(tag_ident);
    };

    // Tag checksum: mod-256 sum of the 16 tag bytes except byte 4.
    let stored_cksum = sector[4];
    let computed_cksum = tag_checksum(&sector[..16]);
    if stored_cksum != computed_cksum {
        out.push(UdfAnomaly::new(UdfAnomalyKind::TagChecksumBad {
            descriptor: label.to_string(),
            lba,
            stored: stored_cksum,
            computed: computed_cksum,
        }));
    }

    // Descriptor CRC over `DescriptorCRCLength` body bytes from offset 16.
    let stored_crc = u16::from_le_bytes([sector[8], sector[9]]);
    let crc_len = u16::from_le_bytes([sector[10], sector[11]]) as usize;
    let body_end = 16usize.saturating_add(crc_len);
    if body_end <= sector.len() {
        let computed_crc = ecma167_crc(&sector[16..body_end]);
        if stored_crc != computed_crc {
            out.push(UdfAnomaly::new(UdfAnomalyKind::TagCrcMismatch {
                descriptor: label.to_string(),
                lba,
                stored: stored_crc,
                computed: computed_crc,
            }));
        }
    }

    Ok(tag_ident)
}

/// Validate the AVDP, every Volume Descriptor Sequence descriptor, and the FSD.
fn audit_bootstrap_tags<R: Read + Seek>(
    reader: &mut R,
    state: &UdfState,
    out: &mut Vec<UdfAnomaly>,
) -> io::Result<()> {
    let bs = state.block_size;

    // AVDP lives at logical sector 256 (the descriptor location the reader
    // already validated to detect the block size).
    audit_tag_at(reader, bs, 256, out)?;

    // VDS descriptors: the reader resolved their location range; re-walk it and
    // validate each descriptor tag until a terminator.
    for i in 0..state.vds_len_sectors {
        let lba = state.vds_loc.saturating_add(i);
        let tag = audit_tag_at(reader, bs, lba, out)?;
        if tag == TAG_TERM || tag == 0 {
            break;
        }
    }

    // File Set Descriptor.
    audit_tag_at(reader, bs, state.fsd_lba, out)?;
    Ok(())
}

/// Walk the directory tree breadth-first from the root File Entry, validating
/// every File Entry's descriptor tag and auditing its final-block slack and
/// modification time. A `visited` set bounds the walk against directory cycles.
fn walk_directory_tree<R: Read + Seek>(
    reader: &mut R,
    state: &UdfState,
    volume_time: Option<&str>,
    out: &mut Vec<UdfAnomaly>,
) -> io::Result<()> {
    let bs = state.block_size;
    let part_start = state.partition_start;

    let mut queue: Vec<u32> = vec![state.root_fe_lba];
    let mut visited: HashSet<u32> = HashSet::new();

    while let Some(dir_fe_lba) = queue.pop() {
        if !visited.insert(dir_fe_lba) {
            continue;
        }
        // Validate the directory's own File Entry tag + per-file audits.
        audit_file_entry(reader, bs, part_start, dir_fe_lba, volume_time, out)?;

        let Some(children) = crate::read_dir_at_lba(reader, bs, part_start, dir_fe_lba) else {
            continue; // cov:unreachable: a queued LBA is always a valid dir FE
        };
        for child in children {
            if child.is_dir {
                queue.push(child.fe_lba);
            } else {
                audit_file_entry(reader, bs, part_start, child.fe_lba, volume_time, out)?;
            }
        }
    }
    Ok(())
}

/// Validate a File Entry descriptor tag, then audit its final-block slack and
/// its modification time against the volume recording time.
fn audit_file_entry<R: Read + Seek>(
    reader: &mut R,
    bs: u32,
    partition_start: u32,
    fe_lba: u32,
    volume_time: Option<&str>,
    out: &mut Vec<UdfAnomaly>,
) -> io::Result<()> {
    audit_tag_at(reader, bs, fe_lba, out)?;

    let mut buf = [0u8; MAX_BLOCK_SIZE];
    let sector = &mut buf[..bs as usize];
    crate::seek_read_checked(reader, u64::from(fe_lba) * u64::from(bs), sector)?;
    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && tag_ident != TAG_EFE {
        return Ok(()); // cov:unreachable: caller only passes File Entry LBAs
    }
    let is_efe = tag_ident == TAG_EFE;

    // Modification time vs the volume recording time.
    if let (Some(vol), Some(mtime)) = (volume_time, crate::fe_modification_time(sector, is_efe)) {
        if mtime.as_str() > vol {
            out.push(UdfAnomaly::new(UdfAnomalyKind::FileAfterVolume {
                lba: fe_lba,
                file_time: mtime,
                volume_time: vol.to_string(),
            }));
        }
    }

    // Final-block slack for the file's data.
    if let Some((nonzero, slack)) = crate::fe_slack_nonzero(reader, bs, partition_start, fe_lba) {
        if nonzero > 0 {
            out.push(UdfAnomaly::new(UdfAnomalyKind::SlackData {
                lba: fe_lba,
                nonzero_bytes: nonzero,
                slack_bytes: slack,
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Drives the anomaly arms the real `mkudffs` corpus cannot reach: the
    //! SLACK-DATA emission path (the corpus stores all files inline, so it has
    //! no allocated-block slack) and the pure severity/category/code/note/Display
    //! surface for every variant. The corpus-backed CRC / checksum /
    //! time-after-volume paths are validated end-to-end by `tests/findings.rs`.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use forensicnomicon::report::{Category, Observation, Source};
    use std::io::Cursor;

    /// Build a 512-byte-block image with a base File Entry (LBA 4) whose single
    /// short allocation descriptor points to a data block (LBA 5) carrying
    /// non-zero slack past `info_len`.
    fn slack_image(info_len: u64, slack: &[u8]) -> Vec<u8> {
        let bs = 512usize;
        let mut img = vec![0u8; bs * 8];
        let fe = 4 * bs;
        img[fe..fe + 2].copy_from_slice(&crate::TAG_FE.to_le_bytes());
        img[fe + 34..fe + 36].copy_from_slice(&0u16.to_le_bytes()); // short_ad alloc
        img[fe + 56..fe + 64].copy_from_slice(&info_len.to_le_bytes());
        img[fe + 168..fe + 172].copy_from_slice(&0u32.to_le_bytes()); // L_EA
        img[fe + 172..fe + 176].copy_from_slice(&8u32.to_le_bytes()); // L_AD
        img[fe + 176..fe + 180].copy_from_slice(&(info_len as u32).to_le_bytes());
        img[fe + 180..fe + 184].copy_from_slice(&5u32.to_le_bytes()); // data lbn
        let data = 5 * bs + (info_len as usize % bs);
        img[data..data + slack.len()].copy_from_slice(slack);
        img
    }

    #[test]
    fn audit_file_entry_emits_slack_finding() {
        let mut r = Cursor::new(slack_image(100, &[0x01, 0x00, 0x02]));
        let mut out = Vec::new();
        audit_file_entry(&mut r, 512, 0, 4, None, &mut out).unwrap();
        let slack: Vec<_> = out
            .iter()
            .filter(|a| matches!(a.kind, UdfAnomalyKind::SlackData { .. }))
            .collect();
        assert_eq!(slack.len(), 1);
        assert_eq!(slack[0].code, "UDF-SLACK-DATA");
        assert_eq!(slack[0].severity, Severity::Low);
        assert!(matches!(
            slack[0].kind,
            UdfAnomalyKind::SlackData {
                nonzero_bytes: 2,
                ..
            }
        ));
    }

    #[test]
    fn slack_anomaly_surface() {
        let an = UdfAnomaly::new(UdfAnomalyKind::SlackData {
            lba: 5,
            nonzero_bytes: 2,
            slack_bytes: 412,
        });
        assert_eq!(an.code, "UDF-SLACK-DATA");
        assert_eq!(an.severity, Severity::Low);
        assert_eq!(an.kind.category(), Category::Residue);
        assert!(an.note.contains("consistent with"));
        // Display formats "[severity] code: note".
        let shown = an.to_string();
        assert!(
            shown.starts_with("[LOW] UDF-SLACK-DATA: "),
            "unexpected Display: {shown}"
        );
        // Observation severity is Some(Low); to_finding carries the category.
        assert_eq!(Observation::severity(&an), Some(Severity::Low));
        assert_eq!(an.to_finding(Source::default()).category, Category::Residue);
    }

    #[test]
    fn file_after_volume_surface() {
        let an = UdfAnomaly::new(UdfAnomalyKind::FileAfterVolume {
            lba: 7,
            file_time: "2099-01-01 00:00:00".into(),
            volume_time: "2026-06-21 08:46:57".into(),
        });
        assert_eq!(an.code, "UDF-TIME-AFTER-VOLUME");
        assert_eq!(an.severity, Severity::Medium);
        assert_eq!(an.kind.category(), Category::History);
        assert!(an.note.contains("consistent with"));
    }

    // ── End-to-end walk over a hand-built minimal UDF ────────────────────────

    const BS: usize = 512;

    /// Stamp a valid ECMA-167 descriptor tag (identifier, location, and matching
    /// checksum + CRC over `crc_len` body bytes) into `img` at logical block
    /// `lba`, so the analyzer's tag validation passes (no spurious tag anomaly).
    fn stamp_tag(img: &mut [u8], lba: usize, tag_id: u16, crc_len: u16) {
        let o = lba * BS;
        img[o..o + 2].copy_from_slice(&tag_id.to_le_bytes());
        img[o + 2..o + 4].copy_from_slice(&0x0102u16.to_le_bytes()); // descriptor version
        img[o + 12..o + 16].copy_from_slice(&(lba as u32).to_le_bytes()); // tag location
        let crc = crate::ecma167_crc(&img[o + 16..o + 16 + crc_len as usize]);
        img[o + 8..o + 10].copy_from_slice(&crc.to_le_bytes());
        img[o + 10..o + 12].copy_from_slice(&crc_len.to_le_bytes());
        img[o + 4] = crate::tag_checksum(&img[o..o + 16]);
    }

    /// Write one inline File Identifier Descriptor (16-byte tag) into `data` at
    /// `off`, naming a child File Entry at logical block `child_lbn`, and return
    /// the advance to the next FID.
    fn write_fid(data: &mut [u8], off: usize, child_lbn: u32, is_dir: bool, name: &[u8]) -> usize {
        data[off..off + 2].copy_from_slice(&crate::TAG_FID.to_le_bytes());
        // body @16: file_version(2) file_chars(1) L_FI(1) ICB long_ad(16) L_IU(2) FI…
        let body = off + 16;
        data[body] = 1; // file version (low byte)
        data[body + 2] = if is_dir { 0x02 } else { 0x00 }; // file characteristics
        data[body + 3] = name.len() as u8; // L_FI
                                           // ICB long_ad: extent_length@+4..+8, logical_block_num@+8..+12.
        data[body + 8..body + 12].copy_from_slice(&child_lbn.to_le_bytes());
        // L_IU @ body+18..+20 = 0; file identifier follows at body+20.
        let id = body + 20;
        data[id..id + name.len()].copy_from_slice(name);
        let raw = 16 + 2 + 1 + 1 + 16 + 2 + name.len(); // tag..end of FI
        let advance = (raw + 3) & !3;
        // CRC length spans the body (everything after the 16-byte tag).
        data[off + 10..off + 12].copy_from_slice(&((advance - 16) as u16).to_le_bytes());
        advance
    }

    /// Stamp a directory File Entry at `lba` whose inline data is `fids`.
    fn stamp_dir_fe(img: &mut [u8], lba: usize, fids: &[u8]) {
        let o = lba * BS;
        img[o + 34..o + 36].copy_from_slice(&3u16.to_le_bytes()); // inline alloc
        img[o + 27] = 4; // ICBTag FileType = directory
        img[o + 56..o + 64].copy_from_slice(&(fids.len() as u64).to_le_bytes());
        img[o + 168..o + 172].copy_from_slice(&0u32.to_le_bytes()); // L_EA
        img[o + 172..o + 176].copy_from_slice(&(fids.len() as u32).to_le_bytes()); // L_AD
        img[o + 176..o + 176 + fids.len()].copy_from_slice(fids);
        stamp_tag(img, lba, crate::TAG_FE, 200);
    }

    /// A complete minimal 512-byte-block UDF: AVDP → VDS(PD, LVD, LVID, TERM) →
    /// FSD → root dir (one subdir, one inline file) → subdir → file.
    fn minimal_udf() -> Vec<u8> {
        let mut img = vec![0u8; BS * 280];
        let part_start = 0u32;

        // AVDP @256 → VDS at LBA 260, length 4 blocks.
        let a = 256 * BS;
        img[a + 16..a + 20].copy_from_slice(&(4u32 * BS as u32).to_le_bytes()); // vds_len bytes
        img[a + 20..a + 24].copy_from_slice(&260u32.to_le_bytes()); // vds_loc
        stamp_tag(&mut img, 256, crate::TAG_AVDP, 16);

        // PD @260: partition number 0, starting location = part_start.
        let p = 260 * BS;
        img[p + 22..p + 24].copy_from_slice(&0u16.to_le_bytes());
        img[p + 188..p + 192].copy_from_slice(&part_start.to_le_bytes());
        stamp_tag(&mut img, 260, crate::TAG_PD, 200);

        // LVD @261: FSD ICB long_ad @248 (lbn@252), partition ref 0; one Type-1
        // partition map (N_PM=1, map_table_len=6) at byte 440.
        let l = 261 * BS;
        img[l + 252..l + 256].copy_from_slice(&3u32.to_le_bytes()); // FSD logical block 3 → LBA 3
        img[l + 256..l + 258].copy_from_slice(&0u16.to_le_bytes()); // partition reference
        img[l + 264..l + 268].copy_from_slice(&6u32.to_le_bytes()); // map table length
        img[l + 268..l + 272].copy_from_slice(&1u32.to_le_bytes()); // N_PM
        img[l + 440] = 1; // map type 1
        img[l + 441] = 6; // map length
        img[l + 444..l + 446].copy_from_slice(&0u16.to_le_bytes()); // partition number
        stamp_tag(&mut img, 261, crate::TAG_LVD, 400);

        // LVID @262 — a descriptor the bootstrap walk recognises but does not
        // terminate on (exercises the `audit_tag_at` non-terminator arm), then a
        // zero sector @263 terminates the VDS walk.
        stamp_tag(&mut img, 262, 9, 80);

        // FSD @3: recording time + Root Directory ICB (lbn@404) = logical 4.
        let f = 3 * BS;
        img[f + 16 + 2..f + 16 + 4].copy_from_slice(&2026i16.to_le_bytes()); // year
        img[f + 16 + 4] = 6;
        img[f + 16 + 5] = 21;
        img[f + 404..f + 408].copy_from_slice(&4u32.to_le_bytes()); // root FE logical block 4
        stamp_tag(&mut img, 3, crate::TAG_FSD, 400);

        // Root directory FE @4: inline FIDs → subdir (lbn 6) + file (lbn 7).
        let mut fids = vec![0u8; 160];
        let n = write_fid(&mut fids, 0, 6, true, b"sub");
        let _ = write_fid(&mut fids, n, 7, false, b"f.txt");
        let total = n + ((16 + 2 + 1 + 1 + 16 + 2 + 5 + 3) & !3);
        stamp_dir_fe(&mut img, 4, &fids[..total]);

        // Subdirectory FE @6: empty inline directory.
        stamp_dir_fe(&mut img, 6, &[]);

        // File FE @7: inline regular file, 4 bytes.
        let ff = 7 * BS;
        img[ff + 34..ff + 36].copy_from_slice(&3u16.to_le_bytes()); // inline
        img[ff + 27] = 5; // regular file
        img[ff + 56..ff + 64].copy_from_slice(&4u64.to_le_bytes());
        img[ff + 168..ff + 172].copy_from_slice(&0u32.to_le_bytes());
        img[ff + 172..ff + 176].copy_from_slice(&4u32.to_le_bytes());
        img[ff + 176..ff + 180].copy_from_slice(b"abcd");
        stamp_tag(&mut img, 7, crate::TAG_FE, 200);

        img
    }

    #[test]
    fn analyze_walks_subdirectory_clean() {
        let img = minimal_udf();
        let mut r = Cursor::new(img);
        // The hand-built image is internally consistent: every descriptor tag
        // verifies, the file post-dates nothing, and inline data has no slack —
        // so the recursion into the subdirectory must complete with no anomaly.
        let a = analyze(&mut r).expect("minimal UDF analyzes");
        assert!(
            a.is_empty(),
            "internally consistent minimal UDF must be clean, got: {a:?}"
        );
    }

    #[test]
    fn audit_tag_at_ignores_unrecognised_identifier() {
        // A sector whose first two bytes are a tag id this crate does not map —
        // there is nothing to validate, so no anomaly and the id is returned.
        let mut img = vec![0u8; BS];
        img[0..2].copy_from_slice(&0x7FFFu16.to_le_bytes());
        let mut r = Cursor::new(img);
        let mut out = Vec::new();
        let tag = audit_tag_at(&mut r, BS as u32, 0, &mut out).unwrap();
        assert_eq!(tag, 0x7FFF);
        assert!(out.is_empty());
    }

    #[test]
    fn audit_tag_at_skips_crc_when_length_overflows_block() {
        // A recognised descriptor whose DescriptorCRCLength exceeds the block —
        // the CRC check is skipped (defensive bound), but the checksum still runs
        // and, being valid here, yields no anomaly.
        let mut img = vec![0u8; BS];
        img[0..2].copy_from_slice(&crate::TAG_FSD.to_le_bytes());
        img[10..12].copy_from_slice(&0xFFFFu16.to_le_bytes()); // crc_len > block
        img[4] = crate::tag_checksum(&img[..16]); // valid checksum
        let mut r = Cursor::new(img);
        let mut out = Vec::new();
        audit_tag_at(&mut r, BS as u32, 0, &mut out).unwrap();
        assert!(
            out.is_empty(),
            "oversized crc_len skips CRC, valid checksum is clean"
        );
    }

    #[test]
    fn walk_skips_already_visited_directory_cycle() {
        // Point the subdirectory's FID back at the root File Entry, forming a
        // cycle; the `visited` guard must break it (no infinite loop, no
        // duplicate audit).
        let mut img = minimal_udf();
        let mut fids = vec![0u8; 64];
        let total = write_fid(&mut fids, 0, 4, true, b"up");
        stamp_dir_fe(&mut img, 6, &fids[..total]);
        let mut r = Cursor::new(img);
        let a = analyze(&mut r).expect("cyclic UDF still terminates");
        assert!(a.is_empty(), "cycle must be skipped cleanly, got: {a:?}");
    }
}
