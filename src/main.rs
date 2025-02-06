use std::cell;
use std::env;
use std::io;
use std::io::Write;
use std::thread;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use ed25519_dalek::Digest;
use ed25519_dalek::Sha512;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256Plus;

fn generate_ed25519_compatible_key() -> [u8; 32] {
    thread_local! {
        static THREAD_RNG: cell::RefCell<Xoshiro256Plus> = cell::RefCell::new(
            Xoshiro256Plus::seed_from_u64(OsRng.next_u64())
        );
    }

    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        // Clamp the key to meet Ed25519 requirements
        key[0] &= 248; // Clear the lowest 3 bits of the first byte
        key[31] &= 127; // Clear the highest bit of the last byte
        key[31] |= 64; // Set the second-highest bit of the last byte

        key
    })
}

fn get_public_key(bits: &mut [u8; 32]) -> [u8; 32] {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;

    let point = &Scalar::from_bytes_mod_order(*bits) * ED25519_BASEPOINT_TABLE;
    let compressed = point.compress().as_bytes().clone();

    compressed
}

fn derive_public_key(private_key_bytes: [u8; 32]) -> [u8; 32] {
    // let secret_key = SecretKey::from_bytes(&private_key_bytes)
    // .expect("Failed to create secret key from private key bytes");
    // let public_key: PublicKey = PublicKey::from(&secret_key);
    // public_key.to_bytes()

    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.update(private_key_bytes);
    hash.copy_from_slice(h.finalize().as_slice());
    digest.copy_from_slice(&hash[..32]);

    let public_key = get_public_key(&mut digest);
    public_key
}

fn get_random_keypair() -> ([u8; 32], [u8; 32]) {
    let private_key = generate_ed25519_compatible_key();
    let public_key = derive_public_key(private_key);

    (private_key, public_key)
}

fn make_key_pair(public_key: [u8; 32], private_key: [u8; 32]) -> [u8; 64] {
    let mut key_pair = [0u8; 64];
    let (one, two) = key_pair.split_at_mut(private_key.len());
    one.copy_from_slice(&private_key);
    two.copy_from_slice(&public_key);
    key_pair
}

fn generate_capital_variations(input: &str) -> Vec<Vec<u8>> {
    let base58_invalid_chars = ['0', 'O', 'I', 'l'];
    let chars: Vec<char> = input.chars().collect();
    let mut results = Vec::new();
    let len = chars.len();
    let mut variations = vec![Vec::new()];

    for i in 0..len {
        let mut new_variations = Vec::new();
        let c = chars[i];

        if c.is_ascii_alphabetic() && !base58_invalid_chars.contains(&c) {
            for v in &variations {
                let mut lower = v.clone();
                lower.push(c.to_ascii_lowercase() as u8);
                new_variations.push(lower);

                let mut upper = v.clone();
                upper.push(c.to_ascii_uppercase() as u8);
                new_variations.push(upper);
            }
        } else {
            for v in &variations {
                let mut unchanged = v.clone();
                unchanged.push(c as u8);
                new_variations.push(unchanged);
            }
        }

        variations = new_variations;
    }

    results.extend(variations);
    results
}

fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    if !args.len() < 3 {
        eprintln!("Please provide correct arguments");
        panic!();
    }

    let prefix_str: &str = &args[1];
    let num_threads: u64 = args[2].parse::<u64>().unwrap();
    let mut enable_all_caps_alt: bool = false;
    let mut enable_search_for_substring: bool = false;

    if args.len() > 3 {
        if args[3] == "--caps" {
            enable_all_caps_alt = true;
        }
        if args[4] == "--substrs" {
            enable_search_for_substring = true;
        }
    }

    let mut prefixs: Vec<Vec<u8>> = vec![prefix_str.as_bytes().to_vec()];

    if enable_all_caps_alt {
        prefixs = generate_capital_variations(prefix_str);
    }

    let prefix_space = &prefixs.len();
    let prefix_len = prefix_str.len();
    let prefix_clone = prefixs.to_vec();
    let mut handles = vec![];

    for _ in 0..num_threads {
        let prefix_len = prefix_len.clone();
        let prefix_space = prefix_space.clone() as u64;
        let prefix_clone_two = prefix_clone.clone();

        let handle = thread::spawn(move || {
            let mut counter = 0;
            let start_time = std::time::Instant::now();
            loop {
                let (private_key, public_key) = get_random_keypair();
                let mut encoded = Vec::new();
                bs58::encode(&public_key).onto(&mut encoded).unwrap();
                counter += 1;
                // let elapsed = start_time.elapsed().as_secs();

                // if counter % 300_000 == 0 {
                //     print!(
                //         "Public key: \x1b[31m{:?}\x1b[0m] -",
                //         bs58::encode(public_key).into_string()
                //     );
                //     println!("Key pair: {:?}", make_key_pair(public_key, private_key));
                // }

                if counter % 100_000 == 0 {
                    let elapsed = start_time.elapsed().as_secs();
                    let raw_key_count = counter * num_threads;
                    let raw_key_rate = counter / elapsed * num_threads;
                    let mut effective_key_count = raw_key_count * prefix_space;
                    let mut effective_key_rate = raw_key_rate * prefix_space;
                    if enable_search_for_substring {
                        let factor: u64 = 32u64 - prefix_len as u64;
                        effective_key_count *= factor;
                        effective_key_rate *= factor;
                    }
                    print!(
                        "\rChecked {} keys. Generating approx {} keys/sec, EFFECTIVE: {}, {}",
                        raw_key_count, raw_key_rate, effective_key_count, effective_key_rate
                    );
                    io::stdout().flush().unwrap();
                }

                fn contains_subsequence_xor(encoded: &[u8], prefix: &[u8]) -> bool {
                    encoded.windows(prefix.len()).any(|window| {
                        window
                            .iter()
                            .zip(prefix.iter())
                            .all(|(&a, &b)| (a ^ b) == 0)
                    })
                }

                for prefix in &prefix_clone_two {
                    let condition: bool;

                    if enable_search_for_substring {
                        condition = contains_subsequence_xor(&encoded, &prefix)
                    } else {
                        condition = encoded.starts_with(prefix);
                    }

                    if condition {
                        println!(
                            "\x1b[32m Found key pair: {:?}\x1b[0m",
                            make_key_pair(public_key, private_key)
                        );
                        println!("Public key: {:?}", bs58::encode(public_key).into_string());
                    }
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
