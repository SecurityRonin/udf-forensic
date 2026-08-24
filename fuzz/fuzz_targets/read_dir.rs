#![no_main]
//! Directory traversal over arbitrary bytes: reads the directory File Entry's
//! data extent, then parses File Identifier Descriptors (FID tag-size detection,
//! per-entry field decode) and OSTA CS0 compressed-Unicode name decoding. The
//! leading bytes steer the addressing (block size, partition start, directory FE
//! LBA); block size is a valid UDF candidate.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const BLOCK_SIZES: [u32; 4] = [2048, 512, 1024, 4096];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if rest.len() < 8 {
        return;
    }
    let block_size = BLOCK_SIZES[(sel as usize) % BLOCK_SIZES.len()];
    let partition_start = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let dir_fe_lba = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);
    let image = &rest[8..];
    let _ = udf_core::read_dir_at_lba(
        &mut Cursor::new(image),
        block_size,
        partition_start,
        dir_fe_lba,
    );
});
