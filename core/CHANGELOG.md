# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/SecurityRonin/udf-forensic/compare/udf-core-v0.1.0...udf-core-v0.2.0) - 2026-11-09

### Added

- *(xattr)* decode the UDF extended-attribute space, re-homed onto udf-core

### Build

- *(deps)* [**breaking**] require published forensic-vfs 0.10, drop the sibling patch

### Fixed

- *(vfs)* report a damaged UDF attribute space instead of "no attributes"
- *(vfs)* bound UDF symlink reads by one block, stop extent reads at the data

## [0.1.0](https://github.com/SecurityRonin/udf-forensic/releases/tag/udf-core-v0.1.0) - 2026-08-24

### Documentation

- *(udf-forensic)* add validation.md — independent oracles + corpora

### Other

- split the reader into udf-core, keeping udf-forensic compatible ([#20](https://github.com/SecurityRonin/udf-forensic/pull/20))
