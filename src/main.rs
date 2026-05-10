use regex::Regex;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

fn main() {
    let pattern = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: ssh-key-gen <regex> [threads]");
        std::process::exit(1);
    });

    let default_threads = (thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        * 3)
        / 4;
    let num_threads: usize = env::args()
        .nth(2)
        .map(|s| s.parse().expect("threads must be a number"))
        .unwrap_or(default_threads.max(1));

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
                    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
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

            std::fs::write("id_ed25519", private_openssh.as_bytes())
                .expect("failed to write private key");
            std::fs::write("id_ed25519.pub", public_openssh.as_bytes())
                .expect("failed to write public key");

            println!("Found after {} keys", total);
            println!("{}", public_openssh);
        }
    }
}
