#![no_main]
//! UDF recognition-sequence scan (LBA 16..32) over a fully attacker-controlled
//! image. Must never panic on arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = udf_core::detect_udf(&mut Cursor::new(data));
});
