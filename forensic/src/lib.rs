//! UDF (Universal Disk Format) forensic analyzer, and the reader it grades over.
//!
//! This crate is the anomaly auditor: [`findings`] emits
//! [`forensicnomicon::report`] observations (descriptor tag CRC/checksum
//! mismatches, file-after-volume ordering, final-block slack) over the parsed
//! model produced by the [`udf_core`] reader.
//!
//! # Reader access is re-exported unchanged
//!
//! The reader used to live in this crate; it now lives in the standalone
//! [`udf_core`], which carries no `forensicnomicon` dependency and keeps a low
//! MSRV so a consumer that only reads a UDF volume (a mount adapter, an
//! archiver) can depend on it alone. For source compatibility this crate
//! **re-exports the entire reader surface**, so existing `udf_forensic::UdfState`
//! / `udf_forensic::detect_udf` / `udf_forensic::vfs::UdfVfs` paths keep
//! resolving and the `vfs` feature keeps working — no consumer change is needed.
//! New reader-only consumers should prefer depending on `udf-core` directly.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod findings;

/// The complete `udf-core` reader surface, re-exported so this crate stays a
/// drop-in for consumers that depended on the reader when it lived here.
pub use udf_core::*;

/// The canonical 5-level severity scale, re-exported at the crate root for
/// convenience (the analyzer grades every finding on it).
pub use forensicnomicon::report::Severity;
