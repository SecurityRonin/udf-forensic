#![no_main]
//! The AVDP → Volume Descriptor Sequence → File Set Descriptor bootstrap over
//! arbitrary bytes: block-size detection, anchor tag, Partition/Logical-Volume
//! descriptors, partition-map parsing (Type 1/2 + Type-2 entity-string
//! classification), and FSD root-ICB resolution. All descriptor tags and length
//! fields are attacker-controlled; the walk must never panic.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // The checked variant surfaces the full AVDP→VDS→FSD chain (I/O errors
    // distinguished from structural negatives); the lenient wrapper folds them.
    let _ = udf_forensic::parse_udf_state_checked(&mut Cursor::new(data));
    let _ = udf_forensic::parse_udf_state(&mut Cursor::new(data));
});
