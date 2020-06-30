# hash-storage-wasm

**hash-storage-wasm** is a Rust library that contains useful functions to work with cryptography issues for the integration with [Hash Storage](https://github.com/fomalhaut88/hash-storage). **hash-storage-wasm** is supposed to be compiled into [WASM](https://en.wikipedia.org/wiki/WebAssembly) and to be used as a Javascript package.

**hash-storage-wasm** is developed for Rust Nightly strictly.

## Installation and build

1. Clone the repository: ```git clone https://github.com/fomalhaut88/hash-storage-wasm.git```
2. Install `wasm-pack`: ```curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh```
3. Build: ```BIGI_BITS=512 wasm-pack build --target no-modules --no-typescript --out-dir target/hash-storage-wasm```
4. Copy the built package wherever it is needed: ```cp -r target/hash-storage-wasm some/path/you/like```

## Functions

| Function | Header | Description |
|---|---|---|
| get_private_key | `fn get_private_key(secret: &str) -> String` | Generate a 256-bit private key by the given secret phrase. |
| get_public_key | `fn get_public_key(private_key: &str) -> String` | Get the public key by the given private key. |
| check_keys | `fn check_keys(private_key: &str, public_key: &str) -> bool` | Check whether private and public keys correspond. |
| encrypt | `fn encrypt(public_key: &str, body: &str) -> String` | Encrypt the given body using [ElGamal encryption algorithm](https://en.wikipedia.org/wiki/ElGamal_encryption). |
| decrypt | `fn decrypt(private_key: &str, body: &str) -> String` | Decrypt the given body using [ElGamal encryption algorithm](https://en.wikipedia.org/wiki/ElGamal_encryption). |
| build_signature | `fn build_signature(private_key: &str, data: &str) -> String` | Build a signature for the given data according to [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm). As a hash function [SHA-256](https://en.wikipedia.org/wiki/SHA-2) is used. |
| check_signature | `fn check_signature(public_key: &str, data: &str, signature: &str) -> bool` | Check whether the signature is valid according to [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm). As a hash function [SHA-256](https://en.wikipedia.org/wiki/SHA-2) is used. |
| build_secret_signature | `fn build_secret_signature(private_key: &str, secret: &str) -> String` | Same as `build_signature` but the hash function is not applied. **secret** must be a HEX representation of a 256-bin integer number. |
| check_secret_signature | `fn check_secret_signature(public_key: &str, secret: &str, secret_signature: &str) -> bool` | Same as `check_signature` but the hash function is not applied. **secret** must be a HEX representation of a 256-bin integer number. |
