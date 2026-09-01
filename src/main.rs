use regex::Regex;
use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

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
                let mut rng = rand::thread_rng();
                let mut local_count: u64 = 0;

                loop {
                    if found.load(Ordering::Relaxed) {
                        return None;
                    }

                    local_count += 1;
                    let key = PrivateKey::random(&mut rng, algorithm.clone())
                        .expect("failed to generate key");
                    let public_openssh = key
                        .public_key()
                        .to_openssh()
                        .expect("failed to serialize public key");
                    let base64_part = public_openssh
                        .split_whitespace()
                        .nth(1)
                        .expect("invalid OpenSSH public key format");

                    if re.is_match(base64_part) {
                        found.store(true, Ordering::Relaxed);
                        let total = total_count.fetch_add(local_count, Ordering::Relaxed) + local_count;
                        return Some((key, total));
                    }

                    if local_count % 100000 == 0 {
                        let total = total_count.fetch_add(100000, Ordering::Relaxed) + 100000;
                        eprintln!("{}", total);
                    }
                }
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
