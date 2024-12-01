use cryptopkg::crypto::error::CryptoError;
use cryptopkg::crypto::error::CryptoErrorCode;
use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Copy, Clone)]
pub enum TsppErrorCode {

    // general
    Unknown,
    IllegalArgument,
    CryptoErrorOccurred,

    // specific
    UnsupportedAlgorithm,
    UnsupportedCipherSuite,
    UnsupportedFragmentType,
    UnsupportedVersion,
    BufferLengthIncorrect,
    BufferTooShort,
    IllegalCipherSuite,
    VerificationFailed,
    UserStreamIsNotReady,
    RecvByeFragment,
    UnsuitableState,
    VersionUnmatched,
    CipherSuiteUnmatched,
    IllegalFragment,
    UnknownAuPublicKey,
    PeerAuthFailed,
    AeadDecryptionFailed,
    HelloPhaseVerificationFailed,

}

#[derive(Debug)]
pub struct TsppError {
    err_code: TsppErrorCode,
    crypto_err_code: Option<CryptoErrorCode>
}

impl TsppError {

    pub fn new(err_code: TsppErrorCode) -> Self {
        return Self{
            err_code: err_code,
            crypto_err_code: None
        };
    }

    pub fn err_code(&self) -> TsppErrorCode {
        return self.err_code;
    }

    pub fn crypto_err_code(&self) -> Option<CryptoErrorCode> {
        return self.crypto_err_code;
    }

}

impl From<CryptoError> for TsppError {

    fn from(err: CryptoError) -> Self {
        return Self{
            err_code: TsppErrorCode::CryptoErrorOccurred,
            crypto_err_code: Some(err.err_code())
        };
    }

}

impl Display for TsppError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "TsppError: {}", match &self.err_code {
            TsppErrorCode::Unknown                   => "unknown",
            TsppErrorCode::IllegalArgument           => "illegal argument",
            TsppErrorCode::CryptoErrorOccurred       => match self.crypto_err_code.unwrap() {
                CryptoErrorCode::Unknown                              => "CRYPTO - unknown",
                CryptoErrorCode::IllegalArgument                      => "CRYPTO - illegal argument",
                CryptoErrorCode::UnsupportedAlgorithm                 => "CRYPTO - unsupported algorithm",
                CryptoErrorCode::BufferLengthIncorrect                => "CRYPTO - buffer length incorrect",
                CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize => "CRYPTO - buffer length is not multiple of block size",
                CryptoErrorCode::CounterOverwrapped                   => "CRYPTO - counter overwrapped",
                CryptoErrorCode::VerificationFailed                   => "CRYPTO - verification failed",
            },
            TsppErrorCode::UnsupportedAlgorithm      => "unsupported algorithm",
            TsppErrorCode::UnsupportedCipherSuite    => "unsupported cipher suite",
            TsppErrorCode::UnsupportedFragmentType   => "unsupported fragment type",
            TsppErrorCode::UnsupportedVersion        => "unsupported version",
            TsppErrorCode::BufferLengthIncorrect     => "buffer length incorrect",
            TsppErrorCode::BufferTooShort            => "buffer too short",
            TsppErrorCode::IllegalCipherSuite        => "illegal cipher suite",
            TsppErrorCode::VerificationFailed        => "verification failed",
            TsppErrorCode::UserStreamIsNotReady      => "user stream is not ready",
            TsppErrorCode::RecvByeFragment           => "recv bye fragment",
            TsppErrorCode::UnsuitableState           => "unsuitable state",
            TsppErrorCode::VersionUnmatched          => "version unmatched",
            TsppErrorCode::CipherSuiteUnmatched      => "cipher suite unmatched",
            TsppErrorCode::IllegalFragment           => "illegal fragment",
            TsppErrorCode::UnknownAuPublicKey        => "unknown au public key",
            TsppErrorCode::PeerAuthFailed            => "peer authentication failed",
            TsppErrorCode::AeadDecryptionFailed => "aead decryption failed",
            TsppErrorCode::HelloPhaseVerificationFailed => "hello phase verification failed",
        });
    }

}

impl Error for TsppError {}