# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vanity SSH key generator. Brute-force generates SSH key pairs until the public key matches a user-supplied regex pattern. Multithreaded, defaults to 75% of available CPU cores.

Supported key types (`-t`): `ed25519` (default) and `ecdsa` (NIST P-256).

**Usage:** `cargo run --release -- [-t ed25519|ecdsa] '<regex>' [threads]`

## Build Commands

- **Build:** `cargo build --release` (release mode important for performance)
- **Run:** `cargo run --release -- [-t ed25519|ecdsa] '<regex>' [threads]`
- **Check:** `cargo check`
- **Make targets:** `make build`, `make check`, `make clean`, `make run ARGS="[-t ecdsa] '<regex>' [threads]"`

## Architecture

Single-file CLI tool (`src/main.rs`). Arguments are parsed by hand: `-t`/`--type`/`--type=` selects the key type, remaining positionals are the regex and thread count. Spawns N threads that each independently generate random keys using `ssh-key` crate, test the public key's OpenSSH representation against a `regex` pattern, and signal other threads via `AtomicBool` when a match is found. Output is written to `id_ed25519`/`id_ed25519.pub` or `id_ecdsa`/`id_ecdsa.pub` in the working directory, matching the key type.

Note that the regex is matched against the base64 blob only, whose fixed prefix differs per key type (`AAAAC3NzaC1lZDI1NTE5AAAAI…` for Ed25519, the much longer `AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB…` for ECDSA), so anchored patterns are not portable between types.

Progress is reported to stderr every 100k keys per thread. Each thread maintains a local counter and periodically flushes to a shared `AtomicU64` to minimize contention.

## Key Dependencies

- `ssh-key` (with `ed25519` + `p256` + `rand_core` features) — key generation and serialization
- `regex` — regex matching
- `rand` — thread-local RNG
- `base64ct` — base64 encoding
