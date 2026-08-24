#![no_main]
//! File Entry / Extended File Entry data extraction over arbitrary bytes:
//! FE/EFE tag dispatch, ICB allocation-type flags, information length, and the
//! short/long allocation-descriptor walk. The leading bytes steer the addressing
//! (block size, partition start, FE LBA) so the fuzzer can land the parse on any
//! offset in the image body; block size is a valid UDF candidate so we exercise
//! the parse logic rather than a caller-contract panic on an out-of-range size.
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
    let fe_lba = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);
    let image = &rest[8..];
    let _ =
        udf_core::read_fe_data(&mut Cursor::new(image), block_size, partition_start, fe_lba);
});
