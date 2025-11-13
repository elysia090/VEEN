set shell := ["bash", "-cu"]

alias d := default

[private]
ensure-toolchain := "rustup component add clippy rustfmt"

help:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

doc:
    cargo doc --workspace --no-deps

test:
    cargo test --workspace

check:
    cargo check --workspace --all-targets

tools:
    {{ensure-toolchain}}

ci:
    just fmt-check
    just lint
    just test
