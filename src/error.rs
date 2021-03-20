/// Errors of this crate
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ed448Error {
    /// The provided array is not in the correct length for the private key.
    ///
    /// It must be [`crate::KEY_LENGTH`].
    ///
    /// See [PrivateKey::from](crate::PrivateKey::from).
    WrongKeyLength,
    /// The provided array is not in the correct length for the public key.
    ///
    /// It must be [`crate::KEY_LENGTH`].
    ///
    /// See [PublicKey::from](crate::PublicKey::from).
    WrongPublicKeyLength,
    /// The provided array is not in the correct length for the signature.
    ///
    /// It must be [`SIG_LENGTH`](crate::SIG_LENGTH).
    ///
    /// See [PublicKey::verify](crate::PublicKey::verify).
    WrongSignatureLength,
    /// The computed point is not valid (maybe forged/altered public key or signature).
    InvalidPoint,
    /// Signature verification failed.
    ///
    /// See [PublicKey::verify](crate::PublicKey::verify).
    InvalidSignature,
    /// The provided context byte array is too long.
    ///
    /// It must not be more than 256 byte.
    ContextTooLong,
}
