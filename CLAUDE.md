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

Single-file CLI tool (`src/main.rs`). Arguments are parsed by hand: `-t`/`--type` selects the key type and `-j`/`--threads` the thread count (both also accept `--flag=value` form); `-h`/`--help` prints a short help screen to stdout and exits 0; the single positional is the regex. Spawns N threads, each running `search_ed25519` or `search_ecdsa` until one matches and signals the rest via `AtomicBool`. Output is written to `id_ed25519`/`id_ed25519.pub` or `id_ecdsa`/`id_ecdsa.pub` in the working directory, matching the key type.

Both searchers avoid per-candidate allocation: a stack blob buffer holds the constant header (`ED_PREFIX`/`EC_PREFIX`) written once, and only the changing tail is base64-encoded into a stack buffer that the regex runs against directly. The prefix lengths (19 and 39 bytes) determine `ED_FROM`/`EC_FROM`, the last 3-byte-aligned offset at or below them — everything before `FROM * 4 / 3` in the base64 output is constant.

**`search_ecdsa` walks incrementally**: `d+1` gives `P+G`, so each candidate costs one point addition plus one affine conversion rather than a full scalar multiplication. This is possible because the OpenSSH ECDSA format stores the private scalar directly — `EcdsaKeypair::NistP256` takes a raw 32-byte scalar. Each thread starts from an independent random scalar and re-seeds every `EC_RESEED_EVERY` steps, so runs of related keys stay short. The found scalar goes through `p256::SecretKey::from_bytes`, which supplies the range check that building from raw bytes skips.

**`search_ed25519` cannot use that trick.** OpenSSH stores the 32-byte *seed* and derives the signing scalar as SHA-512(seed); a chosen scalar has no recoverable seed. `Ed25519Keypair::from_seed` accepts only a seed, so every candidate pays a full SHA-512 plus fixed-base scalar multiplication. This makes Ed25519 roughly 3x slower than ECDSA and the only type where GPU offload would pay off.

Known follow-up: the ECDSA walk does one field inversion per candidate. Montgomery's trick (batch inversion) would amortize that across a batch, but `p256` 0.13.2's `FieldElement` does not implement the `Invert` trait and `primeorder` 0.13.6 has its batched `batch_normalize` commented out (`projective.rs:336`), so `BatchNormalize` is unavailable at this version. `group::Curve::batch_normalize` silently falls back to a per-point loop.

Note that the regex is matched against the base64 blob only, whose fixed prefix differs per key type (`AAAAC3NzaC1lZDI1NTE5AAAAI…` for Ed25519, the much longer `AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB…` for ECDSA), so anchored patterns are not portable between types. For ECDSA the character immediately before the trailing `=` takes only 16 of the 64 base64 values, so some end-anchored patterns are unsatisfiable.

Progress is reported to stderr every `REPORT_EVERY` (100k) keys per thread. The `Progress` struct keeps a local counter and flushes the delta to a shared `AtomicU64` on a threshold (not an exact multiple), tracking a `reported` watermark so the final total isn't double-counted.

## Key Dependencies

- `ssh-key` (with `ed25519` + `p256` + `rand_core` features) — key generation and serialization
- `regex` — regex matching
- `rand` — thread-local RNG
- `base64ct` — allocation-free base64 encoding into fixed buffers
- `ed25519-dalek`, `p256` — used directly in the hot loops, bypassing `ssh-key`'s allocating wrappers. Must stay pinned to the versions `ssh-key` resolves (2.2.x / 0.13.x) so the types unify; check with `cargo tree -d`.
