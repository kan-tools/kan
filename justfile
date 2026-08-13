default: test

test:
    ./scripts/check-rfcs-adrs.sh
    cargo test --workspace

lint:
    ./scripts/check-rfcs-adrs.sh
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

run *ARGS:
    cargo run -p kan -- {{ARGS}}
