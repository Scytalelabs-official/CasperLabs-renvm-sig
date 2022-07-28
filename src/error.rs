use thiserror::Error;

/// Errors that may be returned by RenVm.
#[derive(Debug, Error)]
pub enum RenVmError {
    /// Error forwarded from libsecp256k1.
    #[error(transparent)]
    Secp256k1Error(#[from] libsecp256k1::Error),
    /// Error forwarded from Rustc Hex decode.
    #[error(transparent)]
    RustcHexError(#[from] rustc_hex::FromHexError),
    /// Error forwarded from standard IO error.
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),
}