use crypto::crypto::DiffieHellman;
use crypto::crypto::DigitalSignature;
use crypto::crypto::Hash as HashTrait;
use crypto::crypto::ed25519::Ed25519;
use crypto::crypto::sha3::Sha3256;
use crypto::crypto::x25519::X25519;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use crate::crypto::aead::Aes256Gcm;
use crate::crypto::hash::Hash;
use crate::crypto::hash::HashAlgorithm;
use crate::net::error::NetworkError;
use crate::net::error::NetworkErrorCode;

const BUF_LEN: usize = 0;

pub struct TsppSocket {
    state: TsppState,
    version: Version,
    cipher_suite: CipherSuite,
    secrets: HelloSecrets,
    send_buf: [u8; BUF_LEN],
    recv_buf: [u8; BUF_LEN],
    hash: Hash
}

struct HelloSecrets {
    ke_privkey_len: usize,
    ke_privkey: [u8; 32],
    au_privkey_len: usize,
    au_privkey: [u8; 32]
}

#[derive(PartialEq)]
pub enum TsppState {
    Initial,
    WaitHello,
    RecvHello,
    WaitHelloDone,
    RecvHelloDone,
    BidiUserStream,
    SentBye,
    RecvBye,
    Closed,
}

impl TsppState {

    fn can_send_hello(&self) -> bool {
        return *self == Self::Initial || *self == Self::RecvHello;
    }

    fn can_recv_hello(&self) -> bool {
        return *self == Self::Initial || *self == Self::WaitHello;
    }

    fn can_send_hello_done(&self) -> bool {
        return *self == Self::RecvHello || *self == Self::RecvHelloDone; // roleによってかわる
    }

    fn can_recv_hello_done(&self) -> bool {
        return *self == Self::WaitHelloDone;
    }

    fn can_send_user_stream(&self) -> bool {
        return *self == Self::BidiUserStream || *self == Self::RecvBye;
    }

    fn can_recv_user_stream(&self) -> bool {
        return *self == Self::BidiUserStream || *self == Self::SentBye;
    }

    // fn can_send_hello_bye(&self) -> bool {
//
    // }
//
    // fn can_recv_hello_bye(&self) -> bool {
//
    // }

}

impl Clone for TsppState {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for TsppState {}

impl TsppSocket {

    pub fn new(version: Version, cipher_suite: CipherSuite, au_privkey: &[u8]) -> Result<Self, NetworkError> {

        let c: CipherSuiteConstants = cipher_suite.constants();

        if !match version {
            Version::Version1 => match cipher_suite {
                CipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => true,
                _                                                => false
            },
            _                                                    => false
        } {
            return Err(NetworkError::new(NetworkErrorCode::IllegalCipherSuite));
        }

        if au_privkey.len() != c.au_privkey_len {
            return Err(NetworkError::new(NetworkErrorCode::BufferLengthIncorrect));
        }

        let mut v: Self = Self{
            state: TsppState::Initial,
            version: version,
            cipher_suite: cipher_suite,
            secrets: HelloSecrets{
                ke_privkey_len: c.ke_privkey_len,
                ke_privkey: [0; 32],
                au_privkey_len: c.au_privkey_len,
                au_privkey: [0; 32]
            },
            send_buf: [0; BUF_LEN],
            recv_buf: [0; BUF_LEN],
            hash: cipher_suite.hash()
        };

        v.secrets.au_privkey[..c.au_privkey_len].copy_from_slice(au_privkey);
        let mut csprng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut v.secrets.ke_privkey[..c.ke_privkey_len]);

        return Ok(v);

    }

    pub fn hello_phase_send(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), NetworkError> {
        return match self.state {
            TsppState::Initial        => self.send_hello(buf), // initiator only
            TsppState::RecvHello      => self.send_hello(buf), // acceptor only
            TsppState::RecvHelloDone  => self.send_hello_done(buf),
            TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
            _                        => Err(NetworkError::new(NetworkErrorCode::UnsuitableState))
        };
    }

    pub fn hello_phase_recv(&mut self, buf: &[u8]) -> Result<(usize, TsppState), NetworkError> {
        return match self.state {
            TsppState::Initial        => self.recv_hello(buf), // acceptor only
            TsppState::WaitHello      => self.recv_hello(buf), // initiator only
            TsppState::WaitHelloDone  => self.recv_hello_done(buf),
            TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
            _                        => Err(NetworkError::new(NetworkErrorCode::UnsuitableState))
        };
    }

    pub fn send(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, NetworkError> {

        if self.state.can_send_user_stream() {
            return Err(NetworkError::new(NetworkErrorCode::UserStreamIsNotReady));
        }

        return Ok(0);

    }

    pub fn recv(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, NetworkError> {

        if self.state.can_recv_user_stream() {
            return Err(NetworkError::new(NetworkErrorCode::UserStreamIsNotReady));
        }

        return Ok(0);

    }

    pub fn send_bye(&mut self, buf: &[u8]) -> Result<(), NetworkError> {

        self.state = match self.state {
            TsppState::BidiUserStream => TsppState::SentBye,
            TsppState::RecvBye        => TsppState::Closed,
            _                        => {
                return Err(NetworkError::new(NetworkErrorCode::UnsuitableState));
            }
        };

        return Ok(());

    }

    fn send_hello(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), NetworkError> {

        if !self.state.can_send_hello() {
            return Err(NetworkError::new(NetworkErrorCode::UnsuitableState));
        }

        let h: HelloFragment = HelloFragment::new(self.version, self.cipher_suite, &self.secrets)?;
        let s: usize = h.to_bytes(&mut buf[..])?;

        self.state = if self.state == TsppState::Initial {
            TsppState::WaitHello
        } else {
            TsppState::WaitHelloDone
        };

        return Ok((s, self.state));

    }

    fn recv_hello(&mut self, buf: &[u8]) -> Result<(usize, TsppState), NetworkError> {

        let h: HelloFragment = HelloFragment::from_bytes(buf)?;




        return Ok((0, self.state));

    }

    fn send_hello_done(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), NetworkError> {

        // let h: HelloDoneFragment = HelloDoneFragment::new(self.version, self.cipher_suite, &self.secrets)?;
        // return h.to_bytes(&mut buf[..]);
        return Ok((0, self.state));
    }

    fn recv_hello_done(&mut self, buf: &[u8]) -> Result<(usize, TsppState), NetworkError> {

        // let h: HelloDoneFragment = HelloDoneFragment::from_bytes(buf)?;
        return Ok((0, self.state));

    }

}






struct HelloDoneFragment {
    base: FragmentBaseFields,
    hello_phase_vrf_mac: [u8; 32] // # length can be derived from known.cipher_suite
}

struct UserStreamFragment {
    base: FragmentBaseFields,
    payload: Vec<u8>
}

struct Finish {
    base: FragmentBaseFields
}

struct KeyUpdate {
    base: FragmentBaseFields
}

// struct Secrets {
//
//
//
// }
//
// impl Secrets {
//     fn forget() {}
// }

trait Serializable {
    fn from_bytes(buf: &[u8]) -> Result<Self, NetworkError> where Self: Sized;
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, NetworkError>;
}

enum FragmentType {
    Hello             = 0x00,
    HelloDone         = 0x01,
    UserStream        = 0x02,
    Finish            = 0x03,
    KeyUpdate         = 0x04,
    HelloRetryRequest = 0x05,
    HelloRetry        = 0x06,
}

impl FragmentType {

    const BYTES_NUM: usize = 4;

    fn from_u8(u: u8) -> Result<Self, NetworkError> {
        return match u {
            0x00 => Ok(Self::Hello),
            0x01 => Ok(Self::HelloDone),
            0x02 => Ok(Self::UserStream),
            0x03 => Ok(Self::Finish),
            0x04 => Ok(Self::KeyUpdate),
            0x05 => Ok(Self::HelloRetryRequest),
            0x06 => Ok(Self::HelloRetry),
            _    => Err(NetworkError::new(NetworkErrorCode::UnsupportedFragmentType))
        };
    }

    fn to_u8(&self) -> u8 {
        return match self {
            Self::Hello             => 0x00,
            Self::HelloDone         => 0x01,
            Self::UserStream        => 0x02,
            Self::Finish            => 0x03,
            Self::KeyUpdate         => 0x04,
            Self::HelloRetryRequest => 0x05,
            Self::HelloRetry        => 0x06,
        };
    }

}

impl Clone for FragmentType {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for FragmentType {}

pub enum Version {
    Null     = 0x00000000,
    Version1 = 0x00000001,
}

impl Version {

    const BYTES_NUM: usize = 4;

    fn from_u32(u: u32) -> Result<Self, NetworkError> {
        return match u {
            0x00000000 => Ok(Self::Null),
            0x00000001 => Ok(Self::Version1),
            _          => Err(NetworkError::new(NetworkErrorCode::UnsupportedVersion))
        };
    }

    fn to_u32(&self) -> u32 {
        return match self {
            Self::Null     => 0x00000000,
            Self::Version1 => 0x00000001,
        };
    }

}

impl Clone for Version {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for Version {}

impl Serializable for Version {

    fn from_bytes(buf: &[u8]) -> Result<Self, NetworkError> {

        if buf.len() < Version::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        return Self::from_u32(
            ((buf[0] as u32) << 24) |
            ((buf[1] as u32) << 16) |
            ((buf[2] as u32) <<  8) |
             (buf[3] as u32)
        );

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, NetworkError> {

        if buf.len() < Version::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        let u: u32 = self.to_u32();
        buf[0] = (u >> 24) as u8;
        buf[1] = (u >> 16) as u8;
        buf[2] = (u >>  8) as u8;
        buf[3] =  u        as u8;

        return Ok(Version::BYTES_NUM);

    }

}

#[allow(non_camel_case_types)]
pub enum CipherSuite {
    NULL_NULL_NULL_NULL                 = 0x0000000000000000,
    X25519_Ed25519_AES_128_GCM_SHA3_256 = 0x0000000000000001,
}

impl CipherSuite {

    const BYTES_NUM: usize = 8;

    fn from_u64(u: u64) -> Result<Self, NetworkError> {
        return match u {
            0x0000000000000000 => Ok(Self::NULL_NULL_NULL_NULL),
            0x0000000000000001 => Ok(Self::X25519_Ed25519_AES_128_GCM_SHA3_256),
            _                  => Err(NetworkError::new(NetworkErrorCode::UnsupportedCipherSuite))
        };
    }

    fn to_u64(&self) -> u64 {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => 0x0000000000000000,
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => 0x0000000000000001,
        };
    }

}

impl Clone for CipherSuite {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for CipherSuite {}

impl Serializable for CipherSuite {

    fn from_bytes(buf: &[u8]) -> Result<Self, NetworkError> {

        if buf.len() < CipherSuite::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        return Self::from_u64(
            ((buf[0] as u64) << 56) |
            ((buf[1] as u64) << 48) |
            ((buf[2] as u64) << 40) |
            ((buf[3] as u64) << 32) |
            ((buf[4] as u64) << 24) |
            ((buf[5] as u64) << 16) |
            ((buf[6] as u64) <<  8) |
             (buf[7] as u64)
        );

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, NetworkError> {

        if buf.len() < CipherSuite::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        let u: u64 = self.to_u64();
        buf[0] = (u >> 56) as u8;
        buf[1] = (u >> 48) as u8;
        buf[2] = (u >> 40) as u8;
        buf[3] = (u >> 32) as u8;
        buf[4] = (u >> 24) as u8;
        buf[5] = (u >> 16) as u8;
        buf[6] = (u >>  8) as u8;
        buf[7] =  u        as u8;

        return Ok(CipherSuite::BYTES_NUM);

    }

}

struct FragmentBaseFields {
    frag_type: FragmentType,
    reserved: u8,
    length: u16, // # length of subsequent part
}

impl FragmentBaseFields {

    const BYTES_NUM: usize = 4;

    pub fn new(frag_type: FragmentType) -> Self {
        return Self{
            frag_type: frag_type,
            reserved: 0,
            length: 0
        };
    }

}

impl Serializable for FragmentBaseFields {

    fn from_bytes(buf: &[u8]) -> Result<Self, NetworkError> {

        if buf.len() < FragmentBaseFields::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        return Ok(Self{
            frag_type: FragmentType::from_u8(buf[0])?,
            reserved: buf[1],
            length: ((buf[2] as u16) << 8) | (buf[3] as u16)
        });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, NetworkError> {

        if buf.len() < FragmentBaseFields::BYTES_NUM {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        buf[0] = self.frag_type.to_u8();
        buf[1] = self.reserved;
        buf[2] = (self.length >> 8) as u8;
        buf[3] = self.length as u8;

        return Ok(FragmentBaseFields::BYTES_NUM);

    }

}

struct HelloFragment {
    base: FragmentBaseFields,
    version: Version,
    cipher_suite: CipherSuite,
    random: [u8; 64],
    ke_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_signature: [u8; 64] // # length can be derived from self.cipher_suite
}

impl HelloFragment {

    fn new(version: Version, cipher_suite: CipherSuite, secrets: &HelloSecrets) -> Result<Self, NetworkError> {

        let mut v: Self =  Self{
            base: FragmentBaseFields::new(FragmentType::Hello),
            version: version,
            cipher_suite: cipher_suite,
            random: [0; 64],
            ke_pubkey: [0; 32],
            au_pubkey: [0; 32],
            au_signature: [0; 64]
        };

        let mut csprng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut v.random[..]);

        let c: CipherSuiteConstants = cipher_suite.constants();

        return match v.cipher_suite {
            CipherSuite::NULL_NULL_NULL_NULL => Err(NetworkError::new(NetworkErrorCode::IllegalCipherSuite)),
            CipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                if secrets.ke_privkey.len() != c.ke_privkey_len || secrets.au_privkey.len() != c.au_privkey_len {
                    return Err(NetworkError::new(NetworkErrorCode::BufferLengthIncorrect));
                }

                let sign_input: [u8; 0] = [];
                // msg := (au_signature以外のfrag)

                if let Err(_) = X25519::compute_public_key(
                    &secrets.ke_privkey[..secrets.ke_privkey_len],
                    &mut v.ke_pubkey[..c.ke_pubkey_len]
                ) {
                    return Err(NetworkError::new(NetworkErrorCode::CryptoErrorOccurred));
                }

                if let Err(_) = Ed25519::compute_public_key_oneshot(
                    &secrets.au_privkey[..secrets.au_privkey_len],
                    &mut v.au_pubkey[..c.au_pubkey_len]
                ) {
                    return Err(NetworkError::new(NetworkErrorCode::CryptoErrorOccurred));
                }

                if let Err(_) = Ed25519::sign_oneshot(
                    &secrets.au_privkey[..secrets.au_privkey_len],
                    &sign_input[..],
                    &mut v.au_signature[..c.au_signature_len]
                ) {
                    return Err(NetworkError::new(NetworkErrorCode::CryptoErrorOccurred));
                }

                Ok(v)

            },
        };

    }

}

impl Serializable for HelloFragment {

    fn from_bytes(buf: &[u8]) -> Result<Self, NetworkError> {

        let l: usize = FragmentBaseFields::BYTES_NUM + Version::BYTES_NUM + CipherSuite::BYTES_NUM + 64;
        if buf.len() < l {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        let cipher_suite: CipherSuite = CipherSuite::from_bytes(&buf[8..])?;
        let c: CipherSuiteConstants = cipher_suite.constants();

        let l: usize = l + c.ke_pubkey_len + c.au_pubkey_len + c.au_signature_len;
        if buf.len() < l {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        let mut v: Self = Self{
            base: FragmentBaseFields::from_bytes(&buf[..])?,
            version: Version::from_bytes(&buf[4..])?,
            cipher_suite: cipher_suite,
            random: [0; 64],
            ke_pubkey: [0; 32],
            au_pubkey: [0; 32],
            au_signature: [0; 64]
        };

        let t1: usize = 80 + c.ke_pubkey_len;
        let t2: usize = t1 + c.au_pubkey_len;
        v.random.copy_from_slice(&buf[16..80]);
        v.ke_pubkey[..c.ke_pubkey_len].copy_from_slice(&buf[80..t1]);
        v.au_pubkey[..c.au_pubkey_len].copy_from_slice(&buf[t1..t2]);
        v.au_signature[..c.au_signature_len].copy_from_slice(&buf[t2..(t2 + c.au_signature_len)]);

        return Ok(v);

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, NetworkError> {

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let len: usize =
            FragmentBaseFields::BYTES_NUM +
            Version::BYTES_NUM +
            CipherSuite::BYTES_NUM +
            64 +
            c.ke_pubkey_len +
            c.au_pubkey_len +
            c.au_signature_len;

        if buf.len() < len {
            return Err(NetworkError::new(NetworkErrorCode::BufferTooShort));
        }

        self.base.to_bytes(&mut buf[..]).unwrap();
        self.version.to_bytes(&mut buf[4..]).unwrap();
        self.cipher_suite.to_bytes(&mut buf[8..]).unwrap();
        let t1: usize = 80 + c.ke_pubkey_len;
        let t2: usize = t1 + c.au_pubkey_len;
        buf[16..80].copy_from_slice(&self.random[..]);
        buf[80..t1].copy_from_slice(&self.ke_pubkey[..c.ke_pubkey_len]);
        buf[t1..t2].copy_from_slice(&self.au_pubkey[..c.au_pubkey_len]);
        buf[t2..(t2 + c.au_signature_len)].copy_from_slice(&self.au_signature[..c.au_signature_len]);

        return Ok(len);

    }

}

struct CipherSuiteConstants {
    ke_privkey_len: usize,
    ke_pubkey_len: usize,
    ke_secret_len: usize,
    au_privkey_len: usize,
    au_pubkey_len: usize,
    au_signature_len: usize,
    aead_key_len: usize,
    aead_tag_len: usize,
    hash_msg_dgst_len: usize
}

impl CipherSuite {

    fn constants(&self) -> CipherSuiteConstants {
        return match self {
            Self::NULL_NULL_NULL_NULL => CipherSuiteConstants{
                ke_privkey_len: 0,
                ke_pubkey_len: 0,
                ke_secret_len: 0,
                au_privkey_len: 0,
                au_pubkey_len: 0,
                au_signature_len: 0,
                aead_key_len: 0,
                aead_tag_len: 0,
                hash_msg_dgst_len: 0
            },
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => CipherSuiteConstants{
                ke_privkey_len: X25519::PRIVATE_KEY_LEN,
                ke_pubkey_len: X25519::PUBLIC_KEY_LEN,
                ke_secret_len: X25519::SHARED_SECRET_LEN,
                au_privkey_len: Ed25519::PRIVATE_KEY_LEN,
                au_pubkey_len: Ed25519::PUBLIC_KEY_LEN,
                au_signature_len: Ed25519::SIGNATURE_LEN,
                aead_key_len: Aes256Gcm::KEY_LEN,
                aead_tag_len: Aes256Gcm::TAG_LEN,
                hash_msg_dgst_len: Sha3256::MESSAGE_DIGEST_LEN
            },
        };
    }

    fn hash(&self) -> Hash {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => Hash::new(HashAlgorithm::Null),
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => Hash::new(HashAlgorithm::Sha3256),
        };
    }

}