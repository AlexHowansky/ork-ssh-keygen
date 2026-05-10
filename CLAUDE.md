# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vanity SSH key generator. Brute-force generates Ed25519 SSH key pairs until the public key matches a user-supplied regex pattern. Multithreaded, defaults to 75% of available CPU cores.

**Usage:** `cargo run --release -- '<regex>' [threads]`

## Build Commands

- **Build:** `cargo build --release` (release mode important for performance)
- **Run:** `cargo run --release -- '<regex>' [threads]`
- **Check:** `cargo check`
- **Make targets:** `make build`, `make check`, `make clean`, `make run ARGS="'<regex>' [threads]"`

## Architecture

Single-file CLI tool (`src/main.rs`). Spawns N threads that each independently generate random Ed25519 keys using `ssh-key` crate, test the public key's OpenSSH representation against a `regex` pattern, and signal other threads via `AtomicBool` when a match is found. Output is written to `id_ed25519` and `id_ed25519.pub` in the working directory.

Progress is reported to stderr every 100k keys per thread. Each thread maintains a local counter and periodically flushes to a shared `AtomicU64` to minimize contention.

## Key Dependencies

- `ssh-key` (with `ed25519` + `rand_core` features) — key generation and serialization
- `regex` — regex matching
- `rand` — thread-local RNG
- `base64ct` — base64 encoding
