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

hub-run args="-- --help":
    cargo run -p veen-hub -- {{args}}

cli args="-- help":
    cargo run -p veen-cli -- {{args}}

selftest suite="core":
    cargo run -p veen-selftest -- {{suite}}

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
