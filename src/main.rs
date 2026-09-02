use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use rand::RngCore;
use regex::Regex;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair};
use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

/// Fixed header of an `ssh-ed25519` public key blob: `u32(11) "ssh-ed25519" u32(32)`.
/// The 32-byte key follows, for 51 bytes total (a clean multiple of 3, so the base64
/// is exactly 68 chars with no padding).
const ED_PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
const ED_BLOB: usize = 51;
const ED_B64: usize = 68;
/// Last 3-byte-aligned offset at or below `ED_PREFIX.len()` (19). Everything before it
/// is constant, so each candidate only re-encodes `blob[18..]` into `b64[24..]`.
const ED_FROM: usize = 18;

/// Fixed header of an `ecdsa-sha2-nistp256` blob: `u32(19) "ecdsa-sha2-nistp256"
/// u32(8) "nistp256" u32(65)`. The 65-byte SEC1 point follows, for 104 bytes total.
const EC_PREFIX: &[u8] =
    b"\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00\x41";
const EC_BLOB: usize = 104;
const EC_B64: usize = 140;
/// 39 is already 3-byte aligned, so the point starts exactly at base64 char 52.
const EC_FROM: usize = 39;

/// Keys between progress reports, per thread.
const REPORT_EVERY: u64 = 100_000;

/// Steps before the ECDSA walk picks a fresh random starting scalar.
const EC_RESEED_EVERY: u64 = 4_000_000;

const USAGE: &str = "Usage: ork-ssh-keygen [-t ed25519|ecdsa] [-j N] <regex>";

fn usage() -> ! {
    eprintln!("{}", USAGE);
    std::process::exit(1);
}

fn help() -> ! {
    println!(
        "ork-ssh-keygen \u{2014} vanity SSH key generator

{}

Brute-forces SSH key pairs until the base64 body of the public key
matches <regex>.

Options:
  -t, --type <TYPE>   Key type: ed25519 (default) or ecdsa (NIST P-256)
  -j, --threads <N>   Worker threads (default: 75% of available cores)
  -h, --help          Show this help

Output is written to id_ed25519 / id_ed25519.pub, or id_ecdsa /
id_ecdsa.pub for -t ecdsa, in the current directory.

Examples:
  ork-ssh-keygen 'cafe'
  ork-ssh-keygen -t ecdsa -j 8 'AAAA.*d00d$'",
        USAGE
    );
    std::process::exit(0);
}

/// Maps a `-t` value to its algorithm and the base filename used for output.
fn key_type(name: &str) -> Option<(Algorithm, &'static str)> {
    match name.to_ascii_lowercase().as_str() {
        "ed25519" | "ssh-ed25519" => Some((Algorithm::Ed25519, "id_ed25519")),
        "ecdsa" | "nistp256" | "ecdsa-sha2-nistp256" => Some((
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            "id_ecdsa",
        )),
        _ => None,
    }
}

/// Progress bookkeeping shared with the other worker threads.
struct Progress<'a> {
    found: &'a AtomicBool,
    total: &'a AtomicU64,
    count: u64,
    reported: u64,
}

impl Progress<'_> {
    /// Records `n` more candidates, flushing to the shared counter every
    /// `REPORT_EVERY`. A threshold rather than an exact multiple, since the ECDSA
    /// walk advances the count a whole batch at a time.
    fn tick(&mut self, n: u64) {
        self.count += n;
        let delta = self.count - self.reported;
        if delta >= REPORT_EVERY {
            self.reported = self.count;
            eprintln!("{}", self.total.fetch_add(delta, Ordering::Relaxed) + delta);
        }
    }

    /// Flushes the not-yet-reported remainder and returns the global total.
    fn finish(&self) -> u64 {
        let delta = self.count - self.reported;
        self.total.fetch_add(delta, Ordering::Relaxed) + delta
    }
}

/// Base64 is ASCII by construction, so this never fails.
fn as_str(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("base64 output is valid ASCII")
}

/// Ed25519 search. Every candidate costs a full SHA-512 plus a fixed-base scalar
/// multiplication: the OpenSSH format stores the 32-byte *seed* and derives the
/// signing scalar as SHA-512(seed), so there is no way to walk the scalar
/// incrementally and still have a seed to write out.
fn search_ed25519(re: &Regex, progress: &mut Progress) -> Option<PrivateKey> {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];

    let mut blob = [0u8; ED_BLOB];
    blob[..ED_PREFIX.len()].copy_from_slice(ED_PREFIX);
    let mut b64 = [0u8; ED_B64];
    Base64::encode(&blob, &mut b64).expect("base64 buffer sized for blob");

    loop {
        if progress.found.load(Ordering::Relaxed) {
            return None;
        }

        rng.fill_bytes(&mut seed);
        let verifying = SigningKey::from_bytes(&seed).verifying_key();
        blob[ED_PREFIX.len()..].copy_from_slice(verifying.as_bytes());
        // Only the tail changed; chars before ED_FROM * 4 / 3 are fixed by the prefix.
        Base64::encode(&blob[ED_FROM..], &mut b64[ED_FROM * 4 / 3..])
            .expect("base64 buffer sized for tail");

        progress.tick(1);
        if re.is_match(as_str(&b64)) {
            return Some(Ed25519Keypair::from_seed(&seed).into());
        }
    }
}

/// ECDSA P-256 search. Unlike Ed25519 the OpenSSH format stores the private scalar
/// directly, so consecutive candidates can be walked as d+1 / P+G — one point
/// addition plus one affine conversion each, instead of a full scalar multiplication.
fn search_ecdsa(re: &Regex, progress: &mut Progress) -> Option<PrivateKey> {
    let mut rng = rand::thread_rng();

    let mut blob = [0u8; EC_BLOB];
    blob[..EC_PREFIX.len()].copy_from_slice(EC_PREFIX);
    let mut b64 = [0u8; EC_B64];
    Base64::encode(&blob, &mut b64).expect("base64 buffer sized for blob");

    let generator = ProjectivePoint::GENERATOR;
    let mut scalar = *p256::NonZeroScalar::random(&mut rng).as_ref();
    let mut point = generator * scalar;
    let mut since_reseed = 0u64;

    loop {
        if progress.found.load(Ordering::Relaxed) {
            return None;
        }

        // Restart from a fresh random scalar periodically, so a run of related keys
        // stays short and the walk can never approach the group order.
        if since_reseed >= EC_RESEED_EVERY {
            scalar = *p256::NonZeroScalar::random(&mut rng).as_ref();
            point = generator * scalar;
            since_reseed = 0;
        }

        let affine: p256::AffinePoint = point.to_affine();
        let encoded = affine.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        progress.tick(1);
        since_reseed += 1;

        if bytes.len() == EC_BLOB - EC_PREFIX.len() {
            blob[EC_PREFIX.len()..].copy_from_slice(bytes);
            // Only the tail changed; chars before EC_FROM * 4 / 3 are fixed by the prefix.
            Base64::encode(&blob[EC_FROM..], &mut b64[EC_FROM * 4 / 3..])
                .expect("base64 buffer sized for tail");

            if re.is_match(as_str(&b64)) {
                // from_bytes rejects zero and anything >= the group order, which is
                // the range check skipped by building the key from a raw scalar.
                let secret = p256::SecretKey::from_bytes(&scalar.to_bytes())
                    .expect("walked scalar is a valid P-256 private key");
                return Some(
                    EcdsaKeypair::NistP256 {
                        public: encoded,
                        private: secret.into(),
                    }
                    .into(),
                );
            }
        }

        scalar += Scalar::ONE;
        point += generator;
    }
}

fn main() {
    let mut type_arg: Option<String> = None;
    let mut threads_arg: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--type=") {
            type_arg = Some(value.to_string());
        } else if arg == "-t" || arg == "--type" {
            match args.next() {
                Some(value) => type_arg = Some(value),
                None => {
                    eprintln!("Missing value for {}", arg);
                    usage();
                }
            }
        } else if let Some(value) = arg.strip_prefix("--threads=") {
            threads_arg = Some(value.to_string());
        } else if arg == "-j" || arg == "--threads" {
            match args.next() {
                Some(value) => threads_arg = Some(value),
                None => {
                    eprintln!("Missing value for {}", arg);
                    usage();
                }
            }
        } else if arg == "-h" || arg == "--help" {
            help();
        } else if arg.starts_with('-') && arg != "-" {
            eprintln!("Unknown option: {}", arg);
            usage();
        } else {
            positional.push(arg);
        }
    }

    let (algorithm, key_name) = match type_arg {
        Some(name) => key_type(&name).unwrap_or_else(|| {
            eprintln!("Unknown key type: {}", name);
            usage();
        }),
        None => (Algorithm::Ed25519, "id_ed25519"),
    };

    let mut positional = positional.into_iter();
    let pattern = match positional.next() {
        Some(pattern) => pattern,
        None => usage(),
    };
    if positional.next().is_some() {
        eprintln!("Too many arguments");
        usage();
    }

    let default_threads = (thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        * 3)
        / 4;
    let num_threads: usize = match threads_arg {
        Some(value) => match value.parse() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("thread count must be a positive number, got: {}", value);
                usage();
            }
        },
        None => default_threads.max(1),
    };

    eprintln!("Using {} threads", num_threads);

    // Validate regex before spawning threads
    Regex::new(&pattern).unwrap_or_else(|e| {
        eprintln!("Invalid regex: {}", e);
        std::process::exit(1);
    });

    let found = Arc::new(AtomicBool::new(false));
    let total_count = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let pattern = pattern.clone();
            let algorithm = algorithm.clone();
            let found = Arc::clone(&found);
            let total_count = Arc::clone(&total_count);

            thread::spawn(move || {
                let re = Regex::new(&pattern).unwrap();
                let mut progress = Progress {
                    found: &found,
                    total: &total_count,
                    count: 0,
                    reported: 0,
                };

                let key = match algorithm {
                    Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP256,
                    } => search_ecdsa(&re, &mut progress),
                    _ => search_ed25519(&re, &mut progress),
                }?;

                found.store(true, Ordering::Relaxed);
                Some((key, progress.finish()))
            })
        })
        .collect();

    for handle in handles {
        if let Some((private_key, total)) = handle.join().expect("thread panicked") {
            let private_openssh = private_key
                .to_openssh(LineEnding::LF)
                .expect("failed to serialize private key");
            let public_openssh = private_key
                .public_key()
                .to_openssh()
                .expect("failed to serialize public key");

            std::fs::write(key_name, private_openssh.as_bytes())
                .expect("failed to write private key");
            std::fs::write(format!("{}.pub", key_name), public_openssh.as_bytes())
                .expect("failed to write public key");

            println!("Found after {} keys", total);
            println!("{}", public_openssh);
        }
    }
}
