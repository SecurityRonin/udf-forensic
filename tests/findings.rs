//! Forensic findings analyzer tests.
//!
//! Two tiers (per the fleet test-data-provenance standard):
//! - **Tier 1 / true-negative on real data:** the committed `mkudffs` corpus
//!   (`tests/data/*.img`, provenance in `tests/data/README.md`) is clean —
//!   `mkudffs` writes correct ECMA-167 tag checksums + CRCs, references every
//!   File Entry, and stamps file times at the volume recording time — so the
//!   analyzer must surface NO structural anomaly. The CRC/checksum checks are
//!   self-validating against ECMA-167 (no external oracle needed); the
//!   independent `udfinfo` oracle reconciliation for the volume layout lives in
//!   `src/lib.rs::real_media_tests`.
//! - **Tier 2 / positive on a derived fixture:** each anomaly is driven by
//!   surgically corrupting one field of a real image (a documented mutation of a
//!   real artifact, not a hand-built byte blob), so the positive path is
//!   exercised against an otherwise-genuine structure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use udf_forensic::findings::{analyze, UdfAnomalyKind};
use udf_forensic::Severity;

const PLAIN: &[u8] = include_bytes!("data/udf_plain.img");
const VAT: &[u8] = include_bytes!("data/udf_vat.img");
const SPAR: &[u8] = include_bytes!("data/udf_spar.img");

fn anomalies(image: &[u8]) -> Vec<udf_forensic::findings::UdfAnomaly> {
    let mut r = Cursor::new(image.to_vec());
    analyze(&mut r).expect("analyze must not error on a readable image")
}

// ── Tier 1: clean real corpus is a true negative ─────────────────────────────

#[test]
fn real_plain_image_is_clean() {
    let a = anomalies(PLAIN);
    assert!(
        a.is_empty(),
        "a clean mkudffs hd image must yield no anomalies, got: {a:?}"
    );
}

#[test]
fn real_vat_image_is_clean() {
    let a = anomalies(VAT);
    assert!(
        a.is_empty(),
        "a clean mkudffs cdr/VAT image must yield no anomalies, got: {a:?}"
    );
}

#[test]
fn real_spar_image_is_clean() {
    let a = anomalies(SPAR);
    assert!(
        a.is_empty(),
        "a clean mkudffs dvdrw/sparable image must yield no anomalies, got: {a:?}"
    );
}

// ── Tier 2: corrupt-tag fixtures drive the positive path ─────────────────────

/// Corrupting a descriptor-CRC byte (the AVDP body, byte 16 of LBA 256) must
/// surface a `UDF-TAG-CRC-MISMATCH` — the recorded CRC no longer matches the
/// (now-mutated) body. Self-validating against ECMA-167.
#[test]
fn corrupt_avdp_crc_detected() {
    let mut img = PLAIN.to_vec();
    // udf_plain is 512-byte blocks; AVDP at LBA 256 → byte 256*512.
    let avdp = 256 * 512;
    // Flip a byte in the descriptor *body* (after the 16-byte tag) so the stored
    // DescriptorCRC mismatches but the tag checksum (which covers only the tag)
    // stays valid — isolating the CRC check.
    img[avdp + 16] ^= 0xFF;
    let a = anomalies(&img);
    assert!(
        a.iter()
            .any(|x| matches!(x.kind, UdfAnomalyKind::TagCrcMismatch { .. })
                && x.code == "UDF-TAG-CRC-MISMATCH"),
        "a flipped AVDP body byte must yield UDF-TAG-CRC-MISMATCH, got: {a:?}"
    );
}

/// Corrupting a tag byte that the checksum covers (and fixing nothing) must
/// surface `UDF-TAG-CHECKSUM-BAD`.
#[test]
fn corrupt_avdp_checksum_detected() {
    let mut img = PLAIN.to_vec();
    let avdp = 256 * 512;
    // Byte 6 (TagSerialNumber) is in the checksum's coverage but outside the
    // CRC body — mutating it breaks the checksum without (necessarily) the CRC.
    img[avdp + 6] ^= 0xFF;
    let a = anomalies(&img);
    assert!(
        a.iter()
            .any(|x| matches!(x.kind, UdfAnomalyKind::TagChecksumBad { .. })
                && x.code == "UDF-TAG-CHECKSUM-BAD"),
        "a flipped AVDP tag byte must yield UDF-TAG-CHECKSUM-BAD, got: {a:?}"
    );
}

/// Setting a File Entry's modification-time year past the volume's File Set
/// Descriptor recording time must surface `UDF-TIME-AFTER-VOLUME`. The root File
/// Entry of `udf_plain` is an Extended File Entry at LBA 263 (512-byte blocks),
/// whose modification time lives at byte offset 92 of the descriptor; byte 94 is
/// the high byte of its little-endian `i16` year. Bumping it to 2099 makes the
/// file post-date the 2026 volume recording time.
#[test]
fn file_after_volume_detected() {
    let mut img = PLAIN.to_vec();
    let fe = 263 * 512;
    // ModificationTime year (i16 LE) at FE offset 92+2 = 94. 2099 = 0x0833 →
    // low byte 0x33 at 94, high byte 0x08 at 95.
    img[fe + 94] = 0x33;
    img[fe + 95] = 0x08;
    let a = anomalies(&img);
    assert!(
        a.iter()
            .any(|x| matches!(x.kind, UdfAnomalyKind::FileAfterVolume { .. })
                && x.code == "UDF-TIME-AFTER-VOLUME"),
        "an FE modification time past the volume time must yield UDF-TIME-AFTER-VOLUME, got: {a:?}"
    );
}

// ── Observation / derivation contract ────────────────────────────────────────

#[test]
fn severity_and_code_are_derived_and_stable() {
    let k = UdfAnomalyKind::TagCrcMismatch {
        descriptor: "AVDP".into(),
        lba: 256,
        stored: 0x1234,
        computed: 0x5678,
    };
    let an = udf_forensic::findings::UdfAnomaly::new(k);
    assert_eq!(an.code, "UDF-TAG-CRC-MISMATCH");
    assert_eq!(an.severity, Severity::High);
    assert!(an.note.contains("consistent with"));
}

#[test]
fn observation_maps_to_finding() {
    use forensicnomicon::report::{Category, Observation, Source};
    let an = udf_forensic::findings::UdfAnomaly::new(UdfAnomalyKind::TagChecksumBad {
        descriptor: "FSD".into(),
        lba: 261,
        stored: 1,
        computed: 2,
    });
    let f = an.to_finding(Source::default());
    assert_eq!(f.code, "UDF-TAG-CHECKSUM-BAD");
    assert_eq!(f.category, Category::Integrity);
}
