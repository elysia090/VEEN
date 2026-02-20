set shell := ["bash", "-cu"]

alias d := default
alias b := build
alias t := test
alias l := lint

[private]
ensure-toolchain := "rustup component add clippy rustfmt"

default: fmt-check lint test

help:
    @just --list

build:
    cargo build --workspace

release:
    cargo build --release --workspace

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

doc:
    cargo doc --workspace --no-deps

hub-run args="-- --help":
    cargo run -p veen-hub -- {{args}}

cli args="-- help":
    cargo run -p veen-cli -- {{args}}

selftest suite="core":
    cargo run -p veen-selftest -- {{suite}}

perf args="":
    cargo run -p veen-selftest -- perf {{args}}

test:
    cargo test --workspace

test-verbose:
    cargo test --workspace -- --nocapture

check:
    cargo check --workspace --all-targets

tools:
    {{ensure-toolchain}}

ci:
    just fmt-check
    just lint
    just test

clean:
    cargo clean
