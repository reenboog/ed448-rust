#[derive(Debug)]
pub enum Ed448Error {
    WrongKeyLength,
    WrongPublicKeyLength,
    WrongSignatureLength,
    WrongEncodedPointLength,
    InvalidPoint,
    InvalidSignature,
    ContextTooLong,
    MessageTooLong,
}
