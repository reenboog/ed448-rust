# Ed448-Rust

This is an implementation of Edwards-Curve Digital Signature Algorithm (EdDSA)
from the [RFC8032](https://tools.ietf.org/html/rfc8032) in pure Rust,
but only the ed448 support is implemented.

_This is direct port of the Python code in the RFC, so it's the same warning
as it_

> **Note: This code is not intended for production.  Although it should**
> **produce correct results for every input, it is slow and makes no**
> **attempt to avoid side-channel attacks.**

## Usage

```rust
use core::convert::TryFrom;
use rand_core::{RngCore, OsRng};
use ed448_rust::{PrivateKey, PublicKey};

fn main () {
    // Generate a new random private key
    let private_key = PrivateKey::new(&mut OsRng);

    // Store the key
    let pkey_stored = private_key.as_bytes();

    // Load a stored key before using it, or generating the public key
    let private_key = PrivateKey::try_from(pkey_stored).unwrap();

    // Extract associated public key
    let public_key = PublicKey::from(&private_key);

    // Store the public key
    let pubkey_stored = public_key.as_byte();

    // Sign a message without context
    let signature = private_key.sign(b"Message to sign", None).unwrap();
    // Sign a message with a context
    let signature_ctx = private_key.sign(b"Message to sign", Some(&[0x01, 0xA6])).unwrap();
    // Sign a pre-hashed message without context
    let signature_ph = private_key.sign_ph(b"Message to sign", None).unwrap();

    // Verify the signature without context
    assert!(public_key.verify(b"Message to sign", &signature, None).is_ok());
    // Verify the signature with context
    assert!(public_key.verify(b"Message to sign", &signature_ctx, Some(&[0x01, 0xA6])).is_ok());
    // Verify the signature with the pre-hash and without context
    assert!(public_key.verify_ph(b"Message to sign", &signature_ph, None).is_ok());
}
```

##
