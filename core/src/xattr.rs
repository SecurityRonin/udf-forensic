//! UDF extended attributes (ECMA-167 4/14.10).
//!
//! A File Entry's `L_EA` bytes hold an **Extended Attribute Header Descriptor**
//! (tag 262) followed by a contiguous run of typed attribute records. Until now
//! this crate read `L_EA` only to skip past it and reach the allocation
//! descriptors, so the attributes were located and discarded.
//!
//! ## These are not POSIX extended attributes
//!
//! Every other filesystem in this fleet stores attributes as name/value pairs.
//! UDF does not: an attribute is a TYPED record, and only two of the types carry
//! anything resembling a name.
//!
//! | type | meaning | named? |
//! |---|---|---|
//! | 1 | Character Set Information | no |
//! | 3 | Alternate Permissions | no |
//! | 5 | File Times | no |
//! | 6 | Information Times | no |
//! | 12 | Device Specification | no |
//! | 2048 | Implementation Use | **`EntityID`** |
//! | 65536 | Application Use | **`EntityID`** |
//!
//! `setfattr` cannot write any of them and the Linux UDF driver does not present
//! them as xattrs, so ground truth here comes from an authoring tool rather than
//! from a mount.
//!
//! ## What is validated, and what is not
//!
//! The header and the Implementation Use record are checked against bytes
//! `mkudffs` wrote (`tests/data/udf_vat.img`, reproducible from the generator
//! command recorded beside it).
//!
//! **No real sample of the other record types was obtainable** — `mkudffs`
//! emits none at any media type or revision that it accepts. So every record is
//! decoded to its type, subtype, length and raw bytes, and only the two named
//! forms are interpreted further. The rest are [`UdfEaKind::Other`]: present,
//! visible, and explicitly not interpreted. That is the honest position —
//! decoding a File Times record from the spec alone would produce timestamps
//! nothing here could check, and a wrong timestamp presented as fact is worse
//! than a raw record a reader can go and examine.

use safe_read::{le_u16, le_u32};

/// Length of the Extended Attribute Header Descriptor: a 16-byte descriptor tag
/// plus `ImplementationAttributesLocation` and `ApplicationAttributesLocation`.
const EA_HEADER_LEN: usize = 24;

/// `Extended Attribute Header Descriptor` tag identifier (ECMA-167 4/14.10.1).
const TAG_EA_HEADER: u16 = 262;

/// Minimum bytes of any attribute record: type(4) subtype(1) reserved(3)
/// length(4), plus the 4-byte use-length the two named forms carry.
const EA_RECORD_MIN: usize = 16;

/// Offset of the use-payload length within an Implementation/Application Use
/// record (`ImplementationUseLength` / `ApplicationUseLength`).
const USE_LEN_OFF: usize = 12;
/// Offset of the `EntityID` within an Implementation/Application Use record.
const ENTITY_ID_OFF: usize = 16;
/// An `EntityID` (ECMA-167 1/7.4): flags(1) identifier(23) suffix(8).
const ENTITY_ID_LEN: usize = 32;
/// Offset of the identifier text within an `EntityID`, past its flags byte.
const ENTITY_ID_TEXT: usize = 1;
/// Length of the identifier text within an `EntityID`.
const ENTITY_ID_TEXT_LEN: usize = 23;

/// `Implementation Use Extended Attribute` (ECMA-167 4/14.10.8).
const EA_TYPE_IMPL_USE: u32 = 2048;
/// `Application Use Extended Attribute` (ECMA-167 4/14.10.9).
const EA_TYPE_APP_USE: u32 = 65536;

/// A ceiling on how many records one EA space may yield.
///
/// The EA space is bounded by `L_EA` (a `u32`) and every record must advance the
/// cursor, so this cannot be reached by well-formed input; it exists so a
/// hostile image cannot turn a large `L_EA` into an unbounded allocation.
const MAX_RECORDS: usize = 4096;

/// What kind of UDF extended attribute a record is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UdfEaKind {
    /// Implementation Use (type 2048), named by its `EntityID`.
    ImplementationUse {
        /// The `EntityID` identifier text, e.g. `*UDF VAT LVExtension`.
        identifier: String,
    },
    /// Application Use (type 65536), named by its `EntityID`.
    ApplicationUse {
        /// The `EntityID` identifier text.
        identifier: String,
    },
    /// Any other attribute type.
    ///
    /// Deliberately NOT decoded further. No real sample of these types was
    /// available to validate a decode against, so the record is surfaced with
    /// its type and raw bytes instead of being interpreted into fields that
    /// nothing could check. A reader loses nothing — [`UdfExtendedAttribute::raw`]
    /// carries every byte.
    Other,
}

/// One extended attribute record from a File Entry's EA space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UdfExtendedAttribute {
    /// `Attribute Type` (ECMA-167 4/14.10.2).
    pub attr_type: u32,
    /// `Attribute Subtype`.
    pub attr_subtype: u8,
    /// `Attribute Length`, including the record's header and its padding to the
    /// next 4-byte boundary. This is what advances the walk.
    pub length: u32,
    /// The interpreted form, for the two record types that carry a name.
    pub kind: UdfEaKind,
    /// The record's bytes, verbatim and complete — header included.
    ///
    /// Carried so a consumer can examine anything this crate chose not to
    /// interpret, which is most of the type space.
    pub raw: Vec<u8>,
}

impl UdfExtendedAttribute {
    /// The attribute's name, when it has one.
    ///
    /// `None` for every record type except Implementation Use and Application
    /// Use — UDF genuinely does not name the others, and inventing a label
    /// would present a name the format never gave.
    /// The attribute's value.
    ///
    /// For the two named record types this is the **use-payload**: the bytes
    /// past the common header and the 32-byte `EntityID`, bounded by the
    /// record's own declared use length. Both offsets are checked by arithmetic
    /// that closes against the declared record length on the reference sample
    /// (48 + 146 = 194, padded to 196).
    ///
    /// For every other type it is the whole record. UDF identifies no payload
    /// within them, so slicing at a guessed offset would present some arbitrary
    /// interior bytes as the attribute's value. Returning the record says
    /// exactly what is known.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        match self.kind {
            UdfEaKind::ImplementationUse { .. } | UdfEaKind::ApplicationUse { .. } => {
                let len = le_u32(&self.raw, USE_LEN_OFF) as usize;
                let start = ENTITY_ID_OFF + ENTITY_ID_LEN;
                // A declared length overrunning the record is not trusted: fall
                // back to the whole record rather than silently shortening the
                // value to whatever happens to fit.
                self.raw.get(start..start + len).unwrap_or(&self.raw)
            }
            UdfEaKind::Other => &self.raw,
        }
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            UdfEaKind::ImplementationUse { identifier }
            | UdfEaKind::ApplicationUse { identifier } => Some(identifier),
            UdfEaKind::Other => None,
        }
    }
}

/// Parse a File Entry's extended-attribute space.
///
/// `ea` is the `L_EA` bytes beginning at the File Entry's extended-attribute
/// area. An empty slice yields an empty list: a file with no EA space is
/// ordinary, not an error.
///
/// Returns `None` when the space is present but its header descriptor is not an
/// Extended Attribute Header Descriptor — that is a malformed structure, and
/// reporting "no attributes" for it would hide the damage.
///
/// Records are walked sequentially from the end of the header rather than by
/// following the header's `ImplementationAttributesLocation` /
/// `ApplicationAttributesLocation` offsets. The records are contiguous, so the
/// sequential walk sees every one of them, including any class the two offsets
/// do not point at.
///
/// A record whose declared length overruns the space, or which does not advance
/// the cursor, ENDS the walk and is dropped. The records are packed with no
/// terminator, so once a length is untrustworthy there is nowhere safe to
/// resume; emitting a truncated record would present partial bytes as the
/// attribute's real contents.
#[must_use]
pub fn parse_extended_attributes(ea: &[u8]) -> Option<Vec<UdfExtendedAttribute>> {
    if ea.is_empty() {
        return Some(Vec::new());
    }
    if ea.len() < EA_HEADER_LEN {
        return None;
    }
    let tag = le_u16(ea, 0);
    if tag != TAG_EA_HEADER {
        return None;
    }

    let mut out = Vec::new();
    let mut off = EA_HEADER_LEN;
    while off + EA_RECORD_MIN <= ea.len() && out.len() < MAX_RECORDS {
        let attr_type = le_u32(ea, off);
        // safe-read has no single-byte reader; a checked get keeps the
        // panic-free guarantee without hand-rolling one.
        let attr_subtype = ea.get(off + 4).copied().unwrap_or(0);
        let length = le_u32(ea, off + 8);
        let len = length as usize;

        // A zero (or sub-minimum) length would never advance the cursor; an
        // over-long one would read past the space the File Entry declared.
        if len < EA_RECORD_MIN {
            break;
        }
        let Some(raw) = ea.get(off..off + len) else {
            break;
        };

        let kind = match attr_type {
            EA_TYPE_IMPL_USE => entity_identifier(raw).map_or(UdfEaKind::Other, |identifier| {
                UdfEaKind::ImplementationUse { identifier }
            }),
            EA_TYPE_APP_USE => entity_identifier(raw).map_or(UdfEaKind::Other, |identifier| {
                UdfEaKind::ApplicationUse { identifier }
            }),
            _ => UdfEaKind::Other,
        };

        out.push(UdfExtendedAttribute {
            attr_type,
            attr_subtype,
            length,
            kind,
            raw: raw.to_vec(),
        });
        off += len;
    }
    Some(out)
}

/// The `EntityID` identifier text of an Implementation/Application Use record.
///
/// `None` when the record is too short to hold one — the name is then unknown
/// rather than empty, and the record falls back to [`UdfEaKind::Other`] so the
/// caller is not handed a blank name that looks like a real one.
fn entity_identifier(raw: &[u8]) -> Option<String> {
    let id = raw.get(ENTITY_ID_OFF..ENTITY_ID_OFF + ENTITY_ID_LEN)?;
    let text = id.get(ENTITY_ID_TEXT..ENTITY_ID_TEXT + ENTITY_ID_TEXT_LEN)?;
    // The identifier is a fixed-width field padded with NULs.
    let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    Some(String::from_utf8_lossy(&text[..end]).into_owned())
}
