# ork-ssh-keygen

Vanity SSH key generator. Brute-force generates Ed25519 SSH key pairs until the base64 portion of the public key matches a user-supplied regex pattern.

## Usage

```
make
./target/release/ork-ssh-keygen '<regex>' [threads]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `regex` | Yes | Regex pattern to match against the base64 portion of the public key |
| `threads` | No | Number of threads (defaults to 75% of available CPU cores) |

### Examples

Find a key containing "foo" anywhere in the base64:

```
% ./target/release/ork-ssh-keygen foo
Using 9 threads
Found after 142 keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6ty/f+9+Hu2ffooaZ81v0gdGBFdSLnmyfeNIqPoZ0/
```

Find a key ending with a specific case-insensitive suffix:

```
% ./target/release/ork-ssh-keygen '(?i)alex$'
Using 9 threads
Found after 73474 keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPgeFRunn8oK/wDkHcbPM7uMoxvfaNvRsyl6cwdValEX
```

Use 4 threads:

```
% ./target/release/ork-ssh-keygen 'bar$' 4
Using 4 threads
Found after 95981 keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVmZ9wHfz60iILK+Ul0EE/yHed9qwuIuppvlby72bar
```

## Output

When a match is found, the key pair is written to the working directory:

- `id_ed25519` -- private key (OpenSSH format)
- `id_ed25519.pub` -- public key (OpenSSH format)

The matching public key and total number of keys tested are printed to stdout. Progress updates (total keys tested) are printed to stderr every 100k keys per thread.

## Building

Requires [Rust](https://www.rust-lang.org/tools/install).

## How it works

Each thread independently generates random Ed25519 key pairs using a thread-local CSPRNG, serializes the public key to OpenSSH format, and tests it against the compiled regex. When a match is found, an `AtomicBool` flag signals all other threads to stop. Thread-local counters are periodically flushed to a shared atomic to minimize contention while still reporting progress.

## Performance considerations

The search is pure brute force. Short or common patterns will be found quickly, but the expected number of attempts grows exponentially with the length and specificity of the pattern. Case-insensitive patterns (e.g., `(?i)foo`) will match faster than case-sensitive ones since base64 output contains both upper and lowercase characters.
