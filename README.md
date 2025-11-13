# VEEN

This repository hosts the experimental Rust workspace for the Verifiable End-to-End
Network (VEEN) reference implementation.  The goal of the workspace is to provide a
modern, batteries-included development environment that mirrors the protocol
specification in [`doc/spec.txt`](doc/spec.txt).

## Workspace layout

- [`Cargo.toml`](Cargo.toml) defines a Cargo workspace and shared dependency
  versions.
- [`crates/veen-core`](crates/veen-core) exposes reusable primitives for
  computing protocol hashes and identifiers.
- [`doc/spec.txt`](doc/spec.txt) contains the normative description of the v0.0.1
  wire format.

## Developer guide

The repository ships with tooling commonly used in contemporary Rust projects:

- [`rust-toolchain.toml`](rust-toolchain.toml) pins the toolchain to the latest
  stable release and installs `clippy` and `rustfmt` automatically.
- [`Justfile`](Justfile) exposes convenient recipes for formatting, linting, and
  testing.
- [`clippy.toml`](clippy.toml) denies fallible lint patterns such as
  `unwrap`/`expect` in production code.
- [`rustfmt.toml`](rustfmt.toml) aligns formatting rules across contributors.

### Quickstart

```shell
# Format, lint, and test the entire workspace
just ci

# Run a single check
just test
```

The default crate demonstrates how to derive the canonical `profile_id` hash
from the specification and serves as a foundation for additional protocol
modules.
