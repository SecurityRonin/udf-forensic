# udf-forensic

**Pure-Rust forensic UDF (ECMA-167 / OSTA) reader — volume recognition, partition-map classification, File Entry and directory traversal, and file data over any `Read + Seek`.**

Reads the UDF filesystem on DVD, Blu-ray, and packet-written optical media, with no `unsafe`. Type-2 partitions (Virtual/VAT, Sparable, Metadata) are detected and reported rather than silently mis-read.

## Install

```toml
[dependencies]
udf-forensic = "0.1"
```

## Quick start

```rust
use std::fs::File;

let mut f = File::open("disc.udf")?;
if udf_forensic::detect_udf(&mut f) {
    if let Some(st) = udf_forensic::parse_udf_state(&mut f) {
        println!("{:?}, {} partition map(s)", st.partition_kind, st.partition_map_count);
        if let Some(entries) =
            udf_forensic::read_dir_at_lba(&mut f, st.partition_start, st.root_fe_lba)
        {
            for e in entries {
                println!("  {}  {}  {} bytes", if e.is_dir { "dir " } else { "file" }, e.name, e.size);
            }
        }
    }
}
```

## What it parses

| Capability | Notes |
|---|---|
| Volume recognition | NSR02 / NSR03 sequence detection |
| Partition maps | Physical (Type 1); Virtual / Sparable / Metadata (Type 2) classified + reported |
| Directory traversal | File Entry + File Identifier Descriptors, OSTA CS0 names |
| File data | short/long extent reading from the File Entry |

## Validation

Production code is `#![forbid(unsafe_code)]` with bounds-checked reads, and the bootstrap path distinguishes a genuine read failure (`Err`) from a structural "not UDF" negative (`Ok(None)`). Partition-map classification has tests that assert `mkudffs`-built VAT and Sparable images classify correctly — those fixtures are not yet committed, so the tests skip, and no independent decoding oracle (`udfinfo` / `isoinfo` / `mount`) is wired in yet. The full evidence tiers, current gaps, and recommended oracles are documented in [Validation](validation.md).

## Features

- `serde` — derive `Serialize`/`Deserialize` for partition-kind and entry types.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Sibling filesystems: [`hfsplus-forensic`](https://github.com/SecurityRonin/hfsplus-forensic), [`ext4fs-forensic`](https://github.com/SecurityRonin/ext4fs-forensic), [`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic). Consumed by [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) for optical UDF/bridge discs.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
