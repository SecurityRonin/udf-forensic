[![Crates.io](https://img.shields.io/crates/v/udf-forensic.svg)](https://crates.io/crates/udf-forensic)
[![docs.rs](https://img.shields.io/docsrs/udf-forensic)](https://docs.rs/udf-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/udf-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/udf-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

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

Partition-map classification is checked against **real `mkudffs`-authored images** (VAT and Sparable); those tests skip when the 32 MB fixtures are absent.

## Features

- `serde` — derive `Serialize`/`Deserialize` for partition-kind and entry types.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Sibling filesystems: [`hfsplus-forensic`](https://github.com/SecurityRonin/hfsplus-forensic), [`ext4fs-forensic`](https://github.com/SecurityRonin/ext4fs-forensic), [`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic). Consumed by [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) for optical UDF/bridge discs.

---

[Privacy Policy](https://securityronin.github.io/udf-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/udf-forensic/terms/) · © 2026 Security Ronin Ltd
