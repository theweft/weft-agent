# Run `just` to list recipes. CI runs `just ci` inside `nix develop`.
# weft-verifier is a path dependency: check it out next to this repository (../weft-verifier).

default:
    @just --list

# Format all code and TOML.
fmt:
    cargo fmt --all
    taplo fmt

# Check formatting without changing files.
fmt-check:
    cargo fmt --all --check
    taplo fmt --check

# Lints; warnings are errors.
clippy:
    cargo clippy --locked --workspace --all-targets -- -D warnings

# All tests, including 16 simulation seeds (release build: the simulation is CPU bound).
test:
    cargo test --locked --workspace --release

# More simulation seeds: `just sim 500`. Replay one: `WEFT_SIM_SEED=13 just sim`.
sim seeds="200":
    WEFT_SIM_SEEDS={{seeds}} cargo test --locked --release -p weft-agent --test simulation

# Builds the libraries for the Linux targets (no linker needed for libraries).
targets: (lib-target "x86_64-unknown-linux-gnu") (lib-target "aarch64-unknown-linux-gnu") (lib-target "riscv64gc-unknown-linux-gnu")

[private]
lib-target target:
    cargo build --locked --workspace --lib --target {{target}}

# Licences, advisories, banned crates, allowed sources.
deny:
    cargo deny --all-features check

# Spelling.
typos:
    typos

# Licence and copyright: REUSE compliance, plus an SPDX header in every Rust file.
licenses:
    reuse lint
    @missing=$(git ls-files '*.rs' | while read -r f; do head -2 "$f" | grep -q 'SPDX-''License-Identifier: MIT' || echo "$f"; done); \
    if [ -n "$missing" ]; then echo "missing SPDX header:"; echo "$missing"; exit 1; fi

# API docs; broken links are errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

# Validates requirements/*.sdoc and renders requirements, traceability and ReqIF to target/requirements.
# The coverage gate itself runs as a test (crates/weft-agent/tests/requirements.rs).
requirements:
    strictdoc export . --formats=html,reqif-sdoc --output-dir target/requirements

# NixOS VM end-to-end test (Linux with KVM): shipped systemd units, USB sticks, power cut.
vm:
    nix build .#checks.$(nix eval --impure --raw --expr builtins.currentSystem).l1-vm --override-input weft-verifier git+file:../weft-verifier -L

# The VM test with an interactive driver: start_all(), run steps by hand, inspect the VM.
vm-interactive:
    nix run .#checks.$(nix eval --impure --raw --expr builtins.currentSystem).l1-vm.driverInteractive --override-input weft-verifier git+file:../weft-verifier

# Everything CI checks (the VM test runs as its own CI job).
ci: fmt-check clippy test targets deny licenses typos doc requirements
