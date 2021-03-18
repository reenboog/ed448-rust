use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

pub use crate::error::Ed448Error;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;

mod error;
mod point;
mod private_key;
mod public_key;

pub type Result<T> = core::result::Result<T, Ed448Error>;

pub const KEY_LENGTH: usize = 57;
pub const SIG_LENGTH: usize = 114;

/// Indicate if the message need to be pre-hashed before being signed/verified
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum PreHash {
    /// Pre-hash the message
    True,
    /// Leave the message unchanged
    False,
}

impl From<PreHash> for u8 {
    fn from(hash: PreHash) -> Self {
        match hash {
            PreHash::False => 0,
            PreHash::True => 1,
        }
    }
}

/// Produce a Shake256 for signing/verifying signatures
fn shake256(items: Vec<&[u8]>, ctx: &[u8], pre_hash: PreHash) -> Box<[u8]> {
    let mut shake = Shake256::default()
        .chain(b"SigEd448")
        .chain(&[pre_hash.into(), ctx.len() as u8])
        .chain(ctx);
    for item in items {
        shake.update(item);
    }
    shake.finalize_boxed(114)
}
