use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Copy, Clone)]
pub enum NetworkErrorCode {

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

}

#[derive(Debug)]
pub struct NetworkError {
    err_code: NetworkErrorCode
}

impl NetworkError {

    pub fn new(err_code: NetworkErrorCode) -> Self {
        return Self{
            err_code: err_code,
        };
    }

    pub fn err_code(&self) -> NetworkErrorCode {
        return self.err_code;
    }

}

impl Display for NetworkError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "NetworkError: {}", match &self.err_code {
            NetworkErrorCode::Unknown                 => "unknown",
            NetworkErrorCode::IllegalArgument         => "illegal argument",
            NetworkErrorCode::CryptoErrorOccurred     => "crypto error occurred",
            NetworkErrorCode::UnsupportedAlgorithm    => "unsupported algorithm",
            NetworkErrorCode::UnsupportedCipherSuite  => "unsupported cipher suite",
            NetworkErrorCode::UnsupportedFragmentType => "unsupported fragment type",
            NetworkErrorCode::UnsupportedVersion      => "unsupported version",
            NetworkErrorCode::BufferLengthIncorrect   => "buffer length incorrect",
            NetworkErrorCode::BufferTooShort          => "buffer too short",
            NetworkErrorCode::IllegalCipherSuite      => "illegal cipher suite",
            NetworkErrorCode::VerificationFailed      => "verification failed",
            NetworkErrorCode::UserStreamIsNotReady    => "user stream is not ready",
            NetworkErrorCode::RecvByeFragment         => "recv bye fragment",
            NetworkErrorCode::UnsuitableState         => "unsuitable state",
        });
    }

}

impl Error for NetworkError {}