default: test

test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

run *ARGS:
    cargo run -p kan -- {{ARGS}}
