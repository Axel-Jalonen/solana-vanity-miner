use std::cell;
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
    // PublicKey(compressed, point)
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

fn main() {
    let prefix = b"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let prefix_alt = b"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let prefix_alt_two = b"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let num_threads = 8;
    let prefix_clone = prefix.to_vec();
    let mut handles = vec![];

    for _ in 0..num_threads {
        let prefix_clone = prefix_clone.clone();

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
                    print!(
                        "\rChecked {} keys. Generating approx {} keys/sec",
                        counter * num_threads,
                        counter / elapsed * num_threads
                    );
                    io::stdout().flush().unwrap();
                }

                if encoded.starts_with(&prefix_clone)
                    || encoded.starts_with(&prefix_alt.clone())
                    || encoded.starts_with(&prefix_alt_two.clone())
                {
                    println!(
                        "\x1b[32m Found key pair: {:?}\x1b[0m",
                        make_key_pair(public_key, private_key)
                    );
                    println!("Public key: {:?}", bs58::encode(public_key).into_string());
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
