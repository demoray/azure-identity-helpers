#!/usr/bin/env bash

set -uvex -o pipefail

BUILD_TARGET=${1:-$(rustc --version --verbose | grep ^host: | cut -d ' ' -f 2)}

cd $(dirname ${BASH_SOURCE[0]})/../

which typos || cargo install typos-cli
which cargo-deny || cargo install cargo-deny
which cargo-readme || cargo install cargo-readme

BUILD_COMMON="--locked --profile release --target ${BUILD_TARGET}"

typos
cargo deny check all --hide-inclusion-graph
cargo clippy ${BUILD_COMMON} --all-targets --all-features -- -D warnings -D clippy::pedantic -A clippy::missing_errors_doc -A clippy::module_name_repetitions
cargo clippy ${BUILD_COMMON} --tests --all-targets --all-features -- -D warnings
cargo fmt --check
cargo build ${BUILD_COMMON}
cargo test ${BUILD_COMMON}
cargo readme > README.md
git diff --exit-code README.md
