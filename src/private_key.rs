use std::convert::TryFrom;

use num_bigint::{BigInt, Sign};
use rand_core::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

use crate::{
    point::Point, public_key::PublicKey, shake256, Ed448Error, PreHash, KEY_LENGTH, SIG_LENGTH,
};

pub type PrivateKeyRaw = [u8; KEY_LENGTH];
pub type SeedRaw = [u8; KEY_LENGTH];

pub struct PrivateKey(PrivateKeyRaw);

opaque_debug::implement!(PrivateKey);

impl PrivateKey {
    /// Generate a random key.
    pub fn new<T>(rnd: &mut T) -> Self
    where
        T: CryptoRng + RngCore,
    {
        let mut key = [0; KEY_LENGTH];
        rnd.fill_bytes(&mut key);
        Self::from(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn expand(&self) -> (PrivateKeyRaw, SeedRaw) {
        // 1.  Hash the 57-byte private key using SHAKE256(x, 114), storing the
        //     digest in a 114-octet large buffer, denoted h.
        let h = Shake256::default()
            .chain(self.as_bytes())
            .finalize_boxed(114);
        //     Only the lower 57 bytes are used for generating the public key.
        let mut s = [0; KEY_LENGTH];
        s.clone_from_slice(&h[..KEY_LENGTH]);

        // 2.  Prune the buffer: The two least significant bits of the first
        //     octet are cleared, all eight bits the last octet are cleared, and
        //     the highest bit of the second to last octet is set.
        s[0] &= 0b1111_1100;
        s[56] = 0;
        s[55] |= 0b1000_0000;

        let mut seed = [0; KEY_LENGTH];
        seed.clone_from_slice(&h[KEY_LENGTH..]);

        (s, seed)
    }

    /// Sign with key pair.
    pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>) -> crate::Result<[u8; SIG_LENGTH]> {
        self.sign_real(msg, ctx, PreHash::False)
    }

    /// Sign with key pair. Message is pre-hashed before signed.
    pub fn sign_ph(&self, msg: &[u8], ctx: Option<&[u8]>) -> crate::Result<[u8; SIG_LENGTH]> {
        self.sign_real(msg, ctx, PreHash::True)
    }

    fn sign_real(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        pre_hash: PreHash,
    ) -> crate::Result<[u8; SIG_LENGTH]> {
        let ctx = ctx.unwrap_or(b"");
        if ctx.len() > 255 {
            return Err(Ed448Error::ContextTooLong);
        }

        let msg = match pre_hash {
            PreHash::False => Box::from(msg),
            PreHash::True => Shake256::default().chain(msg).finalize_boxed(64),
        };
        // Expand key.
        let (a, seed) = &self.expand();
        let a = BigInt::from_bytes_le(Sign::Plus, a);
        // Calculate r and R (R only used in encoded form).
        let r = shake256(vec![seed, &msg], ctx, pre_hash);
        let r = BigInt::from_bytes_le(Sign::Plus, r.as_ref()) % Point::l();
        let R = (Point::default() * &r).encode();
        // Calculate h.
        let h = shake256(
            vec![&R, PublicKey::from(a.clone()).as_byte(), &msg],
            ctx,
            pre_hash,
        );
        let h = BigInt::from_bytes_le(Sign::Plus, h.as_ref()) % Point::l();
        // Calculate s.
        let S = (r + h * a) % Point::l();
        // The final signature is a concatenation of R and S.
        let (_sign, mut S_) = S.to_bytes_le();
        S_.resize_with(KEY_LENGTH, Default::default);
        let mut S = [0; KEY_LENGTH];
        S.copy_from_slice(&S_);

        let mut result = [0; SIG_LENGTH];
        result.copy_from_slice(&[R, S].concat());
        Ok(result)
    }
}

impl From<PrivateKeyRaw> for PrivateKey {
    fn from(array: PrivateKeyRaw) -> Self {
        Self(array)
    }
}

impl TryFrom<&'_ [u8]> for PrivateKey {
    type Error = Ed448Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != KEY_LENGTH {
            return Err(Ed448Error::WrongKeyLength);
        }
        let mut key = [0; KEY_LENGTH];
        key.copy_from_slice(bytes);
        Ok(PrivateKey::from(key))
    }
}

impl From<&'_ PrivateKeyRaw> for PrivateKey {
    fn from(bytes: &PrivateKeyRaw) -> Self {
        let mut key = [0; KEY_LENGTH];
        key.copy_from_slice(bytes);
        PrivateKey::from(key)
    }
}
