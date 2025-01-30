# Solana Vanity Prefix Searcher

## Usage

1. (Optionally) Edit `num_threads` in `src/main.rs`
2. Edit `prefix` in `src/main.rs` (Must be valid base58, (the program assumes so)).
3. Build & run in release mode

## Building for linux from MacOS:

Install zibuild, etc. 

```cargo zigbuild --target x86_64-unknown-linux-musl --release```
