//! UDF extended attributes — the EA space of a File Entry.
//!
//! `parse_fe` has always read `L_EA` and used it only to skip PAST the extended
//! attributes to reach the allocation descriptors. The bytes were located and
//! discarded, so a UDF image presented files with no extended attributes.
//!
//! ## UDF EAs are NOT POSIX xattrs
//!
//! This is the important difference from the ext4/XFS/Btrfs decoders. A UDF
//! extended attribute (ECMA-167 4/14.10) is a TYPED record, not a name/value
//! pair. The EA space is an Extended Attribute Header Descriptor (tag 262)
//! followed by records that each carry an attribute type, a subtype and a
//! length:
//!
//! | type | meaning |
//! |---|---|
//! | 1 | Character Set Information |
//! | 3 | Alternate Permissions |
//! | 5 | File Times |
//! | 6 | Information Times |
//! | 12 | Device Specification |
//! | 2048 | **Implementation Use** — carries an `EntityID` name |
//! | 65536 | **Application Use** — carries an `EntityID` name |
//!
//! Only the last two have anything resembling a name, so only those can be
//! presented as named streams. `setfattr` cannot write any of them, and the
//! Linux UDF driver does not surface them as xattrs, which is why this fixture
//! comes from an authoring tool rather than from a mount.
//!
//! ## The oracle is `mkudffs`, and what it proves is bounded
//!
//! `tests/data/udf_vat.img` was authored by `mkudffs` (udftools). Re-running
//! the recorded generator command in a clean container reproduces an image with
//! the EA at the same offset and the same shape, so this is a tool-written
//! structure and not one this crate invented:
//!
//! ```text
//! udf_cdr_0x0150.img: 1 entry with EAs -> [(612352, 261, 220)]
//!     EA type=2048 (ImplUse) len=196 id=b'*UDF VAT LVExtension'
//! ```
//!
//! **The limit, stated plainly:** this fixture exercises the EA header and ONE
//! Implementation Use record. `mkudffs` writes no File Times, Alternate
//! Permissions or Application Use attributes at any media type or revision
//! tried (`hd`/`cdr` x `0x0150`/`0x0201`), so those record types are decoded
//! structurally — type, subtype, length and raw body — and are NOT validated
//! against real samples here. They are surfaced rather than interpreted, so
//! nothing is lost and nothing is asserted that has not been observed.

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use udf_core::{parse_extended_attributes, UdfEaKind};

/// The File Entry carrying the EA, per an independent scan of the image.
const FE_OFFSET: usize = 612_352;
/// `L_EA` at that File Entry.
const EA_LEN: usize = 220;

fn vat_image() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../tests/data/udf_vat.img");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

/// The EA space of that File Entry: base File Entry, so the area starts at +176.
fn ea_space(img: &[u8]) -> &[u8] {
    &img[FE_OFFSET + 176..FE_OFFSET + 176 + EA_LEN]
}

/// The fixture must really carry an EA, or everything below is vacuous.
#[test]
fn the_fixture_really_has_an_ea_space() {
    let img = vat_image();
    let tag = u16::from_le_bytes([img[FE_OFFSET], img[FE_OFFSET + 1]]);
    assert_eq!(
        tag, 261,
        "offset {FE_OFFSET} must be a File Entry (tag 261)"
    );
    let l_ea = u32::from_le_bytes(img[FE_OFFSET + 168..FE_OFFSET + 172].try_into().unwrap());
    assert_eq!(l_ea as usize, EA_LEN, "L_EA must be non-zero and known");
}

/// The EA space decodes to exactly the record `mkudffs` wrote.
#[test]
fn the_implementation_use_attribute_is_decoded() {
    let img = vat_image();
    let eas = parse_extended_attributes(ea_space(&img)).expect("EA space must decode");

    assert_eq!(eas.len(), 1, "mkudffs writes exactly one EA here: {eas:?}");
    let ea = &eas[0];
    assert_eq!(ea.attr_type, 2048, "Implementation Use");
    assert_eq!(ea.attr_subtype, 1);
    // 16-byte common header + 32-byte EntityID + 146 bytes of implementation
    // use = 194, padded to the 4-byte boundary = 196.
    assert_eq!(ea.length, 196);
    assert_eq!(
        ea.kind,
        UdfEaKind::ImplementationUse {
            identifier: "*UDF VAT LVExtension".to_string(),
        },
        "the EntityID names the attribute; got {:?}",
        ea.kind
    );
}

/// The raw body is preserved, so nothing is lost to a partial decode.
#[test]
fn the_raw_body_is_carried_verbatim() {
    let img = vat_image();
    let eas = parse_extended_attributes(ea_space(&img)).unwrap();
    let ea = &eas[0];

    // The body is the whole record including its header, so a consumer can
    // re-examine bytes this crate chose not to interpret.
    assert_eq!(ea.raw.len(), ea.length as usize);
    assert!(
        ea.raw.windows(20).any(|w| w == b"*UDF VAT LVExtension"),
        "the EntityID must be present in the carried bytes"
    );
}

/// A File Entry with `L_EA == 0` has no EA space, and that is not an error.
#[test]
fn an_empty_ea_space_is_not_an_error() {
    assert_eq!(
        parse_extended_attributes(&[]).expect("empty is not an error"),
        Vec::new()
    );
}

/// A truncated EA space must not be reported as a complete decode.
///
/// Refusing beats padding: a short record reported as whole would present
/// truncated bytes as the attribute's real contents.
#[test]
fn a_truncated_record_is_refused_not_padded() {
    let img = vat_image();
    let full = ea_space(&img);
    // Cut the record in half, keeping the header descriptor intact.
    let short = &full[..full.len() / 2];
    let eas = parse_extended_attributes(short).expect("header still decodes");
    assert!(
        eas.is_empty(),
        "a record whose declared length exceeds the space must be dropped, \
         not truncated into a plausible-looking attribute: {eas:?}"
    );
}

/// A named record's VALUE is its use-payload, not the whole record.
///
/// For Implementation Use the payload length is declared at offset 12 and the
/// payload begins at 48, past the common header and the 32-byte `EntityID`.
/// Both are checked by arithmetic that has to close against the record's own
/// declared length: 48 + 146 = 194, padded to the 4-byte boundary = 196.
#[test]
fn a_named_records_value_is_its_payload() {
    let img = vat_image();
    let eas = parse_extended_attributes(ea_space(&img)).unwrap();
    let ea = &eas[0];

    let value = ea.value();
    assert_eq!(
        value.len(),
        146,
        "ImplementationUseLength reads 146 in this record"
    );
    assert!(
        value.len() < ea.raw.len(),
        "the value must be the payload, not the record: {} vs {}",
        value.len(),
        ea.raw.len()
    );
    // The EntityID lives in the header, so it must NOT appear in the value --
    // that is what distinguishes a payload from a raw record.
    assert!(
        !value.windows(20).any(|w| w == b"*UDF VAT LVExtension"),
        "the EntityID belongs to the header, not the payload"
    );
}

/// An unnamed record has no payload the format identifies, so its value is the
/// record itself rather than a guess at where a payload might start.
#[test]
fn an_unnamed_records_value_is_the_whole_record() {
    // A minimal synthetic EA space: header descriptor + one File Times record.
    // Synthetic ON PURPOSE and only for this shape question -- no real sample
    // of a non-ImplUse record was obtainable, so this asserts the FALLBACK
    // behaviour, never that File Times is decoded correctly.
    let mut ea = vec![0u8; 24];
    ea[0] = 262u16.to_le_bytes()[0];
    ea[1] = 262u16.to_le_bytes()[1];
    let mut rec = vec![0u8; 16];
    rec[0..4].copy_from_slice(&5u32.to_le_bytes()); // File Times
    rec[8..12].copy_from_slice(&16u32.to_le_bytes()); // length
    ea.extend_from_slice(&rec);

    let eas = parse_extended_attributes(&ea).expect("decodes");
    assert_eq!(eas.len(), 1);
    assert_eq!(eas[0].kind, UdfEaKind::Other, "type 5 is not interpreted");
    assert_eq!(eas[0].name(), None, "UDF gives this record no name");
    assert_eq!(
        eas[0].value(),
        &eas[0].raw[..],
        "with no identified payload the whole record is the value"
    );
}
