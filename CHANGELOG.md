# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.8](https://github.com/SecurityRonin/udf-forensic/compare/udf-forensic-v0.2.7...udf-forensic-v0.2.8) - 2026-08-24

### Added

- *(vfs)* decode UDF PATH_COMPONENT symlinks

### Documentation

- *(vfs)* stop linking public docs at a private decoder
- *(vfs)* type-1 agreed-location semantics match the kernel break

### Fixed

- *(vfs)* bound a decoded symlink target by the caller's cap
- *(vfs)* walk PATH_COMPONENT records the way udf_pc_to_char does
- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.2.7](https://github.com/SecurityRonin/udf-forensic/compare/udf-forensic-v0.2.6...udf-forensic-v0.2.7) - 2026-08-08

### Documentation

- unshadow vfs's module docs and drop a finding the analyzer cannot emit

### Fixed

- *(docs)* backtick the identifiers clippy's doc_markdown flags

## [0.2.6](https://github.com/SecurityRonin/udf-forensic/compare/udf-forensic-v0.2.5...udf-forensic-v0.2.6) - 2026-08-06

### Fixed

- *(supply-chain)* trust safe-read as ours instead of exempting it

## [0.2.5](https://github.com/SecurityRonin/udf-forensic/compare/udf-forensic-v0.2.4...udf-forensic-v0.2.5) - 2026-08-04

### Fixed

- *(lba)* GREEN - check the address arithmetic the image chooses

## [0.2.4](https://github.com/SecurityRonin/udf-forensic/compare/udf-forensic-v0.2.3...udf-forensic-v0.2.4) - 2026-07-24

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)

### Fixed

- *(vet)* exempt safe-read (new panic-free dep)
- *(security)* panic-free by lint — route fixed-width reads through safe-read

## [0.2.2](https://github.com/SecurityRonin/udf-forensic/compare/v0.2.1...v0.2.2) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5
