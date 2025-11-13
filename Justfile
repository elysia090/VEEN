set shell := ["bash", "-cu"]

alias d := default

[private]
setup-tools := "rustup component add clippy rustfmt"

help:
    @just --list

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

check:
    cargo check --workspace --all-targets

ci:
    just fmt
    just lint
    just test
