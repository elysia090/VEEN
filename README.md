# VEEN

This repository hosts the experimental Rust workspace for the Verifiable End-to-End
Network (VEEN) reference implementation.  The goal of the workspace is to provide a
modern, batteries-included development environment that mirrors the protocol
specifications in [`doc/spec-1.txt`](doc/spec-1.txt) and
[`doc/spec-2.txt`](doc/spec-2.txt).

## Workspace layout

- [`Cargo.toml`](Cargo.toml) defines a Cargo workspace and shared dependency
  versions.
- [`crates/veen-core`](crates/veen-core) exposes reusable primitives for
  computing protocol hashes and identifiers.
- [`crates/veen-hub`](crates/veen-hub) scaffolds the hub runtime described in
  [`doc/GOALS.txt`](doc/GOALS.txt).
- [`crates/veen-cli`](crates/veen-cli) provides the command-line surface for
  exercising hub APIs.
- [`crates/veen-selftest`](crates/veen-selftest) is a placeholder integration
  harness that will eventually orchestrate the end-to-end acceptance suites.
- [`doc/spec-1.txt`](doc/spec-1.txt) contains the normative description of the
  v0.0.1 wire format.
- [`doc/spec-2.txt`](doc/spec-2.txt) specifies the v0.0.1+ operational overlays.

## Developer guide

The repository ships with tooling commonly used in contemporary Rust projects:

- [`rust-toolchain.toml`](rust-toolchain.toml) pins the toolchain to the latest
  stable release and installs `clippy` and `rustfmt` automatically.
- [`Justfile`](Justfile) exposes convenient recipes for formatting, linting, and
  testing.
- Workspace lint configuration in [`Cargo.toml`](Cargo.toml) forbids
  footguns such as `unwrap`/`expect` in production code.
- [`rustfmt.toml`](rustfmt.toml) aligns formatting rules across contributors.

### Quickstart

```shell
# Install required Rust components (clippy and rustfmt)
just tools

# Format, lint, and test the entire workspace
just ci

# Format without mutating files (useful in CI)
just fmt-check

# Generate documentation
just doc

# Launch the hub scaffold (currently emits a not-implemented error)
just hub-run -- --listen 127.0.0.1:8080 --data-dir /tmp/veen-hub

# Explore the CLI surface (commands currently terminate with scaffold errors)
just cli -- keygen --out /tmp/veen-client

# Exercise the self-test harness scaffolding
just selftest core
```

> **Status:** the new binaries are scaffolds. They compile, parse CLI flags,
> and log intent, but they deliberately return `not yet implemented` errors so
> that missing protocol logic is never mistaken for production-ready code.  The
> flows described in [`doc/GOALS.txt`](doc/GOALS.txt) remain the authoritative
> roadmap for filling in the implementations.
