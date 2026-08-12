//! Shared synthetic-UDF fixtures for the in-crate unit tests.
//!
//! The committed `mkudffs` images (`tests/data/*.img`) have empty root
//! directories and store their (absent) data inline, so they cannot exercise
//! directory (FID) traversal, filename decoding, or the short/long allocation
//! extent readers. This module hand-builds a small, reader-faithful UDF image
//! whose root directory holds several files (inline, short-extent, long-extent,
//! UTF-16-named) plus a deliberately-broken directory File Entry, so those
//! paths are driven by real assertions rather than left dark.
//!
//! The byte layout follows ECMA-167 / OSTA UDF exactly as the reader parses it;
//! the expected values the tests assert are derived from that construction (a
//! spec-defined fixture, not an oracle-checked codec output).

#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Logical/physical block size of the synthetic image.
pub(crate) const BS: usize = 512;

// Physical LBAs. `partition_start` is 0, so a File Entry's physical LBA equals
// its logical block number.
pub(crate) const ROOT_FE: u32 = 4;
pub(crate) const SUBDIR_FE: u32 = 5;
pub(crate) const INLINE_FILE_FE: u32 = 6;
pub(crate) const SHORT_FILE_FE: u32 = 7;
pub(crate) const LONG_FILE_FE: u32 = 10;
pub(crate) const UTF16_FILE_FE: u32 = 12;
pub(crate) const BROKEN_DIR_FE: u32 = 13;
pub(crate) const SYMLINK_FE: u32 = 14;

/// Information Length of the short-extent file (600 B ⇒ two 512-B blocks).
pub(crate) const SHORT_FILE_LEN: u64 = 600;
/// Information Length of the long-extent file.
pub(crate) const LONG_FILE_LEN: u64 = 300;

fn w16(img: &mut [u8], o: usize, v: u16) {
    img[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(img: &mut [u8], o: usize, v: u32) {
    img[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(img: &mut [u8], o: usize, v: u64) {
    img[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// One reader-faithful 16-byte-tag File Identifier Descriptor naming a child
/// File Entry at logical block `child_lbn`. `name` is an OSTA CS0 identifier
/// (its first byte is the compression id: 8 = UTF-8, 16 = UTF-16BE).
fn fid(child_lbn: u32, is_dir: bool, is_parent: bool, name: &[u8]) -> Vec<u8> {
    let mut chars = 0u8;
    if is_dir {
        chars |= 0x02;
    }
    if is_parent {
        chars |= 0x08;
    }
    let name_len = name.len();
    // Body after the 16-byte tag: file_chars(1) L_FI(1) ICB long_ad(16) L_IU(2) FI.
    let body_len = 1 + 1 + 16 + 2 + name_len;
    let advance = (16 + body_len + 3) & !3;
    let mut f = vec![0u8; advance];
    w16(&mut f, 0, 257); // TAG_FID
    w16(&mut f, 10, body_len as u16); // DescriptorCRCLength (drives fid_advance)
    f[16] = chars;
    f[17] = name_len as u8;
    w32(&mut f, 22, child_lbn); // ICB long_ad logical_block_num
                                // L_IU @34..36 = 0; the file identifier starts at body+20 == off+36.
    f[36..36 + name_len].copy_from_slice(name);
    f
}

/// Stamp a File Entry (tag 260) at `lba` with the given ICB Tag File Type
/// (4 = directory, 5 = file), allocation type (0 = short, 1 = long, 3 = inline),
/// Information Length, and allocation/inline data area.
fn stamp_fe(img: &mut [u8], lba: u32, file_type: u8, alloc: u16, info_len: u64, ad: &[u8]) {
    let o = lba as usize * BS;
    w16(img, o, 260); // TAG_FE
    img[o + 27] = file_type; // ICB Tag File Type
    w16(img, o + 34, alloc); // ICB flags: allocation type in bits 0..2
    w64(img, o + 56, info_len);
    w32(img, o + 168, 0); // L_EA
    w32(img, o + 172, ad.len() as u32); // L_AD
    img[o + 176..o + 176 + ad.len()].copy_from_slice(ad);
}

fn short_ad(len: u32, pos: u32) -> [u8; 8] {
    let mut a = [0u8; 8];
    a[0..4].copy_from_slice(&len.to_le_bytes()); // extent_length (type 0 = recorded)
    a[4..8].copy_from_slice(&pos.to_le_bytes()); // extent_position (logical block)
    a
}
fn long_ad(len: u32, lbn: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..4].copy_from_slice(&len.to_le_bytes());
    a[4..8].copy_from_slice(&lbn.to_le_bytes());
    a
}

/// A complete 512-byte-block, Type-1 physical-partition UDF image with a
/// populated root directory. Every offset matches what the reader parses; the
/// tag checksum/CRC fields are irrelevant to the reader (only the findings
/// analyzer validates them) and are left zero here.
pub(crate) fn image() -> Vec<u8> {
    let mut img = vec![0u8; BS * 264];

    // AVDP @ LBA 256 → VDS at LBA 260, length 4 blocks.
    let avdp = 256 * BS;
    w16(&mut img, avdp, 2); // TAG_AVDP
    w32(&mut img, avdp + 12, 256); // tag location (detect_block_size requires == 256)
    w32(&mut img, avdp + 16, (4 * BS) as u32); // Main VDS extent length (bytes)
    w32(&mut img, avdp + 20, 260); // Main VDS extent location

    // Partition Descriptor @260: partition 0 starts at physical LBA 0.
    let pd = 260 * BS;
    w16(&mut img, pd, 5); // TAG_PD
    w16(&mut img, pd + 22, 0); // partition number
    w32(&mut img, pd + 188, 0); // partition starting location

    // Logical Volume Descriptor @261: FSD ICB lbn 3, partition ref 0, one
    // Type-1 physical partition map.
    let lvd = 261 * BS;
    w16(&mut img, lvd, 6); // TAG_LVD
    w32(&mut img, lvd + 252, 3); // FSD logical_block_num
    w16(&mut img, lvd + 256, 0); // FSD partition reference
    w32(&mut img, lvd + 264, 6); // Map Table Length
    w32(&mut img, lvd + 268, 1); // N_PM
    img[lvd + 440] = 1; // map type 1
    img[lvd + 441] = 6; // map length
    w16(&mut img, lvd + 444, 0); // partition number

    // File Set Descriptor @3 → root directory File Entry logical block 4.
    let fsd = 3 * BS;
    w16(&mut img, fsd, 256); // TAG_FSD
    w32(&mut img, fsd + 404, 4);

    // Root directory File Entry @4: inline File Identifier Descriptors.
    let mut dir = Vec::new();
    dir.extend_from_slice(&fid(ROOT_FE, true, true, b"")); // parent (skipped by reader)
    dir.extend_from_slice(&fid(SUBDIR_FE, true, false, b"\x08sub"));
    dir.extend_from_slice(&fid(INLINE_FILE_FE, false, false, b"\x08inline.txt"));
    dir.extend_from_slice(&fid(SHORT_FILE_FE, false, false, b"\x08short.bin"));
    dir.extend_from_slice(&fid(LONG_FILE_FE, false, false, b"\x08long.bin"));
    dir.extend_from_slice(&fid(UTF16_FILE_FE, false, false, &[16, 0x00, b'U'])); // UTF-16BE "U"
    dir.extend_from_slice(&fid(BROKEN_DIR_FE, true, false, b"\x08bd"));
    dir.extend_from_slice(&fid(SYMLINK_FE, false, false, b"\x08lnk"));
    // The root directory no longer fits the File Entry's inline area, so it
    // lives in its own block (LBA 15) behind a short allocation descriptor.
    let root_dir_block = 15u32;
    img[root_dir_block as usize * BS..root_dir_block as usize * BS + dir.len()].copy_from_slice(&dir);
    stamp_fe(&mut img, ROOT_FE, 4, 0, dir.len() as u64, &short_ad(dir.len() as u32, root_dir_block));

    // Subdirectory File Entry @5: an empty inline directory.
    stamp_fe(&mut img, SUBDIR_FE, 4, 3, 0, &[]);

    // Symlink File Entry @14: ICB file type 0x0c with an inline PATH_COMPONENT
    // record chain for "../README.txt" (the exact byte layout the Linux UDF
    // driver writes; see tests/data/README.md).
    let symlink_data: [u8; 19] = [
        0x03, 0x00, 0x00, 0x00, // type 3 (".."), len 0, version 0
        0x05, 0x0b, 0x00, 0x00, // type 5 (name), len 11, version 0
        0x08, b'R', b'E', b'A', b'D', b'M', b'E', b'.', b't', b'x', b't',
    ];
    stamp_fe(&mut img, SYMLINK_FE, 0x0c, 3, symlink_data.len() as u64, &symlink_data);

    // Inline file File Entry @6: 4 bytes stored in the ICB.
    stamp_fe(&mut img, INLINE_FILE_FE, 5, 3, 4, b"abcd");

    // Short-extent file File Entry @7: data at LBA 8..=9 (600 B over two blocks).
    stamp_fe(
        &mut img,
        SHORT_FILE_FE,
        5,
        0,
        SHORT_FILE_LEN,
        &short_ad(SHORT_FILE_LEN as u32, 8),
    );
    img[8 * BS..9 * BS].fill(0x41);
    img[9 * BS..9 * BS + 88].fill(0x42);

    // Long-extent file File Entry @10: data at LBA 11 (300 B).
    stamp_fe(
        &mut img,
        LONG_FILE_FE,
        5,
        1,
        LONG_FILE_LEN,
        &long_ad(LONG_FILE_LEN as u32, 11),
    );
    img[11 * BS..11 * BS + LONG_FILE_LEN as usize].fill(0x43);

    // UTF-16-named inline file File Entry @12.
    stamp_fe(&mut img, UTF16_FILE_FE, 5, 3, 4, b"wxyz");

    // Broken directory File Entry @13: ICB Tag File Type says directory, but its
    // L_AD overruns the block, so read_fe_data cannot slice the allocation area
    // and yields None (a directory that resolves as a dir but cannot be read).
    let o = BROKEN_DIR_FE as usize * BS;
    w16(&mut img, o, 260);
    img[o + 27] = 4; // directory
    w16(&mut img, o + 34, 0); // short allocation
    w64(&mut img, o + 56, 0);
    w32(&mut img, o + 168, 0); // L_EA
    w32(&mut img, o + 172, 1000); // L_AD overruns the 512-byte block

    img
}
