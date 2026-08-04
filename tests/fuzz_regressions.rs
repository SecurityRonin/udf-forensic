//! Inputs that once panicked the parser, kept as ordinary tests.
//!
//! These are real reproducers minted by the nightly fuzz job, not hand-authored
//! fixtures — they are the bytes libFuzzer actually found, downloaded from the
//! failing run's artifact. Both crashed with `attempt to add with overflow` on a
//! logical-block address computed from two header fields.
//!
//! They live here rather than only in `fuzz/corpus/` so that `cargo test` fails
//! if the bound regresses. A defect found by fuzzing should not need fuzzing to
//! be caught a second time: the fuzz job runs nightly, the test suite runs on
//! every push.
//!
//! The assertion is deliberately weak on *what* comes back. A malformed image
//! may legitimately parse to `None`, to an error, or even to a structure — the
//! contract under test is only that it returns at all rather than panicking.

// An integration test is a separate crate, so the workspace's panic-free lints
// do not reach it and it carries its own allow — the same shape the fleet
// standard prescribes. A fixture that fails to load should fail loudly.
#![allow(clippy::expect_used)]

use std::io::Cursor;

/// libFuzzer `parse_state` reproducer: overflowed `partition_start + fsd_lbn`
/// while resolving the File Set Descriptor location.
const PARSE_STATE_CRASH: &[u8] = include_bytes!("data/fuzz-crash-parse_state-add-overflow.bin");

/// libFuzzer `read_dir` reproducer: overflowed `partition_start + icb_lbn`
/// while walking a directory's File Identifier Descriptors.
const READ_DIR_CRASH: &[u8] = include_bytes!("data/fuzz-crash-read_dir-add-overflow.bin");

#[test]
fn parse_state_reproducer_does_not_panic() {
    let _ = udf_forensic::parse_udf_state_checked(&mut Cursor::new(PARSE_STATE_CRASH));
    let _ = udf_forensic::parse_udf_state(&mut Cursor::new(PARSE_STATE_CRASH));
}

/// The `read_dir` harness steers addressing from the leading bytes rather than
/// parsing them out of the image, so the reproducer has to be decoded the same
/// way its fuzz target does or it exercises nothing.
#[test]
fn read_dir_reproducer_does_not_panic() {
    const BLOCK_SIZES: [u32; 4] = [2048, 512, 1024, 4096];
    let (&sel, rest) = READ_DIR_CRASH
        .split_first()
        .expect("reproducer is non-empty");
    assert!(rest.len() >= 8, "reproducer carries the addressing prefix");

    let block_size = BLOCK_SIZES[(sel as usize) % BLOCK_SIZES.len()];
    let partition_start = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let dir_fe_lba = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);

    let _ = udf_forensic::read_dir_at_lba(
        &mut Cursor::new(&rest[8..]),
        block_size,
        partition_start,
        dir_fe_lba,
    );
}
