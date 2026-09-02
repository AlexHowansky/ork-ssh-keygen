# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vanity SSH key generator. Brute-force generates SSH key pairs until the public key matches a user-supplied regex pattern. Multithreaded, defaults to 75% of available CPU cores.

Supported key types (`-t`): `ed25519` (default) and `ecdsa` (NIST P-256).

**Usage:** `cargo run --release -- [-t ed25519|ecdsa] [-j N] '<regex>'`

## Build Commands

- **Build:** `cargo build --release` (release mode important for performance)
- **Run:** `cargo run --release -- [-t ed25519|ecdsa] [-j N] '<regex>'`
- **Check:** `cargo check`
- **Make targets:** `make build`, `make linux`, `make windows`, `make check`, `make clean`, `make run ARGS="[-t ecdsa] [-j N] '<regex>'"`

`make build` builds both the native and the Windows binary:

- Native: `target/release/ork-ssh-keygen`
- Windows: `target/x86_64-pc-windows-gnu/release/ork-ssh-keygen.exe`

The Windows build is best-effort — it requires the MinGW linker
(`sudo apt install gcc-mingw-w64-x86-64`) plus `rustup target add x86_64-pc-windows-gnu`.
If `x86_64-w64-mingw32-gcc` isn't on `PATH`, the `windows` target prints a warning and
exits 0 so the native build still succeeds. The linker is pinned in `.cargo/config.toml`.
All dependencies are pure Rust with no C build scripts, so no other cross-compilation
setup is needed.

## Architecture

Single-file CLI tool (`src/main.rs`). Arguments are parsed by hand: `-t`/`--type` selects the key type and `-j`/`--threads` the thread count (both also accept `--flag=value` form); `-h`/`--help` prints a short help screen to stdout and exits 0; the single positional is the regex. Spawns N threads that each independently generate random keys using `ssh-key` crate, test the public key's OpenSSH representation against a `regex` pattern, and signal other threads via `AtomicBool` when a match is found. Output is written to `id_ed25519`/`id_ed25519.pub` or `id_ecdsa`/`id_ecdsa.pub` in the working directory, matching the key type.

Note that the regex is matched against the base64 blob only, whose fixed prefix differs per key type (`AAAAC3NzaC1lZDI1NTE5AAAAI…` for Ed25519, the much longer `AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB…` for ECDSA), so anchored patterns are not portable between types.

Progress is reported to stderr every 100k keys per thread. Each thread maintains a local counter and periodically flushes to a shared `AtomicU64` to minimize contention.

## Key Dependencies

- `ssh-key` (with `ed25519` + `p256` + `rand_core` features) — key generation and serialization
- `regex` — regex matching
- `rand` — thread-local RNG
- `base64ct` — base64 encoding
