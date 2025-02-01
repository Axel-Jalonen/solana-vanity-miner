# Solana Vanity Prefix Searcher

## Usage

1. Configure options:
  - (Automatically binary encoded base58 string) Prefix
    - Your chosen prefix
  - (boolean) All capitals
    - Creates a vector of all legal base58 strings in capital variation from your prefix.
  - (boolean) Substring
    - Searches for substrings, not just prefixs.
  - (Natural number) Edit `num_threads` in `src/main.rs`
    - Number of threads to search with, usually use as many threads as you have cores.
4. Build & run in release mode

## Building for linux from MacOS:

Install zigbuild, etc. 

```cargo zigbuild --target x86_64-unknown-linux-musl --release```
