use cryptopkg::crypto::feature::Aead as AeadFeature;
use cryptopkg::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use cryptopkg::crypto::feature::Hash as HashFeature;
use cryptopkg::crypto::feature::Mac as MacFeature;
use cryptopkg::crypto::util::Aead;
use cryptopkg::crypto::util::AeadAlgorithm;
use cryptopkg::crypto::util::Hash;
use cryptopkg::crypto::util::HashAlgorithm;
use cryptopkg::crypto::util::DigitalSignatureAlgorithm;
use cryptopkg::crypto::aes_aead::Aes128Gcm;
use cryptopkg::crypto::ed25519::Ed25519;
use cryptopkg::crypto::hmac_sha3::HmacSha3256;
use cryptopkg::crypto::sha3::Sha3256;
use cryptopkg::crypto::x25519::X25519;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use crate::net::error::TsppError;
use crate::net::error::TsppErrorCode;

const BUF_LEN: usize = 0;

const MAX_KE_PRIVATE_KEY_LEN: usize = X25519::PRIVATE_KEY_LEN;
const MAX_KE_PUBLIC_KEY_LEN: usize  = X25519::PUBLIC_KEY_LEN;
const MAX_CURRENT_SECRET_LEN: usize = HmacSha3256::MAC_LEN;
const MAX_AU_PRIVATE_KEY_LEN: usize = Ed25519::PRIVATE_KEY_LEN;
const MAX_AU_PUBLIC_KEY_LEN: usize  = Ed25519::PUBLIC_KEY_LEN;
const MAX_MESSAGE_DIGEST_LEN: usize = Sha3256::MESSAGE_DIGEST_LEN;

pub struct TsppSocket {
    state: TsppState,
    version: TsppVersion,
    cipher_suite: TsppCipherSuite,
    role: TsppRole,
    send_buf: [u8; BUF_LEN],
    recv_buf: [u8; BUF_LEN],
    send_aead_iv: [u8; 12],
    recv_aead_iv: [u8; 12],
    send_frag_ctr: u64,
    recv_frag_ctr: u64,
    ke_privkey_buf: [u8; MAX_KE_PRIVATE_KEY_LEN],
    au_privkey_buf: [u8; MAX_AU_PRIVATE_KEY_LEN],
    secret_buf: [u8; MAX_CURRENT_SECRET_LEN],
    send_aead: Aead,
    recv_aead: Aead,
    context_hash: Hash,
}

pub enum TsppState {
    Initial,
    HelloSent,
    HelloRecvd,
    HelloDoneSent,
    HelloDoneRecvd,
    BidiUserStream,
    ByeSent,
    ByeRecvd,
    Closed,
}

pub enum TsppRole {
    ActiveOpener,
    PassiveOpener,
}

impl Clone for TsppRole {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for TsppRole {}

impl PartialEq for TsppRole {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for TsppRole {}

impl TsppState {

    fn can_send_hello(&self, role: TsppRole) -> bool {
        return
            (role == TsppRole::ActiveOpener && *self == Self::Initial) ||
            (role == TsppRole::PassiveOpener && *self == Self::HelloRecvd);
    }

    fn can_recv_hello(&self, role: TsppRole) -> bool {
        return
            (role == TsppRole::ActiveOpener && *self == Self::HelloSent) ||
            (role == TsppRole::PassiveOpener && *self == Self::Initial);
    }

    fn can_send_hello_done(&self, role: TsppRole) -> bool {
        return
            (role == TsppRole::ActiveOpener && *self == Self::HelloDoneRecvd) ||
            (role == TsppRole::PassiveOpener && *self == Self::HelloSent);
    }

    fn can_recv_hello_done(&self, role: TsppRole) -> bool {
        return
            (role == TsppRole::ActiveOpener && *self == Self::HelloRecvd) ||
            (role == TsppRole::PassiveOpener && *self == Self::HelloDoneSent);
    }

    fn can_send_user_stream(&self) -> bool {
        return *self == Self::BidiUserStream || *self == Self::ByeRecvd;
    }

    fn can_recv_user_stream(&self) -> bool {
        return *self == Self::BidiUserStream || *self == Self::ByeSent;
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

impl PartialEq for TsppState {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for TsppState {}

static engine: LazyLock<Mutex<TsppEngine>> = LazyLock::new(|| Mutex::new(TsppEngine::new()));

pub struct TsppEngine {
    inner: HashMap<(usize, Vec<u8>), Vec<u8>>
}

impl TsppEngine {

    pub fn new() -> Self {
        return Self{ inner: HashMap::<(usize, Vec<u8>), Vec<u8>>::new() };
    }

    pub fn insert_known_peer_auth_public_key(algo: DigitalSignatureAlgorithm, pubkey: &[u8]) {
        engine.lock().unwrap().inner.insert((algo as usize, pubkey.to_vec()), pubkey.to_vec());
    }

    pub fn is_known_peer_auth_public_key(algo: DigitalSignatureAlgorithm, pubkey: &[u8]) -> bool {
        return match engine.lock().unwrap().inner.get(&(algo as usize, pubkey.to_vec())) {
            Some(v) => v.as_slice() == pubkey,
            None    => false
        };
    }

}

impl TsppSocket {

    pub fn new(version: TsppVersion, cipher_suite: TsppCipherSuite, role: TsppRole,
        au_privkey: &[u8]) -> Result<Self, TsppError> {

        if !version.check_cipher_suite(cipher_suite) {
            return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite));
        }

        let c: CipherSuiteConstants = cipher_suite.constants();

        if au_privkey.len() != c.au_privkey_len {
            return Err(TsppError::new(TsppErrorCode::BufferLengthIncorrect));
        }

        let mut v: Self = Self{
            state: TsppState::Initial,
            version: version,
            cipher_suite: cipher_suite,
            role: role,
            send_buf: [0; BUF_LEN],
            recv_buf: [0; BUF_LEN],
            send_aead_iv: [0; 12],
            recv_aead_iv: [0; 12],
            send_frag_ctr: 0,
            recv_frag_ctr: 0,
            ke_privkey_buf: [0; MAX_KE_PRIVATE_KEY_LEN],
            au_privkey_buf: [0; MAX_AU_PRIVATE_KEY_LEN],
            secret_buf: [0; MAX_CURRENT_SECRET_LEN],
            send_aead: cipher_suite.aead(&[0; 32][..c.aead_key_len])?,
            recv_aead: cipher_suite.aead(&[0; 32][..c.aead_key_len])?,
            context_hash: cipher_suite.hash()?
        };

        v.au_privkey_buf[..c.au_privkey_len].copy_from_slice(au_privkey);
        let mut csprng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut v.ke_privkey_buf[..c.ke_privkey_len]);

        return Ok(v);

    }

    pub fn hello_phase_send(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), TsppError> {
        return match self.role {
            TsppRole::ActiveOpener => match self.state {
                TsppState::Initial        => self.send_hello(buf),
                TsppState::HelloDoneRecvd => self.send_hello_done(buf),
                TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
                _                         => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            },
            TsppRole::PassiveOpener => match self.state {
                TsppState::HelloRecvd     => {
                    let (s, state): (usize, TsppState) = self.send_hello(buf)?;

                    Ok((s, state))
                },
                TsppState::HelloSent      => self.send_hello_done(buf),
                TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
                _                         => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            }
        };
    }

    pub fn hello_phase_recv(&mut self, buf: &[u8]) -> Result<(usize, TsppState), TsppError> {
        return match self.role {
            TsppRole::ActiveOpener => match self.state {
                TsppState::HelloSent      => {
                    let (r, state): (usize, TsppState) = self.recv_hello(buf)?;

                    Ok((r, state))
                },
                TsppState::HelloRecvd     => self.recv_hello_done(buf),
                TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
                _                         => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            },
            TsppRole::PassiveOpener => match self.state {
                TsppState::Initial        => self.recv_hello(buf),
                TsppState::HelloDoneSent  => self.recv_hello_done(buf),
                TsppState::BidiUserStream => Ok((0, TsppState::BidiUserStream)),
                _                         => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            }
        };
    }

    pub fn send(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, TsppError> {

        if self.state.can_send_user_stream() {
            return Err(TsppError::new(TsppErrorCode::UserStreamIsNotReady));
        }

        return Ok(0);

    }

    pub fn recv(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, TsppError> {

        if self.state.can_recv_user_stream() {
            return Err(TsppError::new(TsppErrorCode::UserStreamIsNotReady));
        }

        return Ok(0);

    }

    pub fn send_bye(&mut self, buf: &[u8]) -> Result<(), TsppError> {

        self.state = match self.state {
            TsppState::BidiUserStream => TsppState::ByeSent,
            TsppState::ByeRecvd       => TsppState::Closed,
            _                         => {
                return Err(TsppError::new(TsppErrorCode::UnsuitableState));
            }
        };

        return Ok(());

    }

    fn send_hello(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), TsppError> {

        if !self.state.can_send_hello(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let s: usize =
            FragmentBaseFields::BYTES_NUM +
            TsppVersion::BYTES_NUM +
            TsppCipherSuite::BYTES_NUM +
            64 +
            c.ke_pubkey_len +
            c.au_pubkey_len +
            c.au_signature_len;

        let mut frag: HelloFragment = HelloFragment{
            base: FragmentBaseFields{
                frag_type: FragmentType::Hello,
                reserved: 0x00,
                length: (s - FragmentBaseFields::BYTES_NUM) as u16
            },
            version: self.version,
            cipher_suite: self.cipher_suite,
            random: [0; 64],
            ke_pubkey: [0; 32],
            au_pubkey: [0; 32],
            au_signature: [0; 64]
        };

        let mut csprng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut frag.random[..]);

        match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                if self.ke_privkey_buf.len() != X25519::PRIVATE_KEY_LEN ||
                    self.au_privkey_buf.len() != Ed25519::PRIVATE_KEY_LEN {
                    return Err(TsppError::new(TsppErrorCode::BufferLengthIncorrect));
                }

                X25519::compute_public_key_oneshot(&self.ke_privkey_buf[..X25519::PRIVATE_KEY_LEN],
                    &mut frag.ke_pubkey[..X25519::PUBLIC_KEY_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                Ed25519::compute_public_key_oneshot(&self.au_privkey_buf[..Ed25519::PRIVATE_KEY_LEN],
                    &mut frag.au_pubkey[..Ed25519::PUBLIC_KEY_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                let mut fb: [u8; 208] = [0; 208];
                frag.to_bytes(&mut fb[..])?;
                let f: usize = frag.len() - Ed25519::SIGNATURE_LEN;

                let mut m: [u8; 32 + Sha3256::MESSAGE_DIGEST_LEN] = [0; 32 + Sha3256::MESSAGE_DIGEST_LEN];
                match self.role {
                    TsppRole::ActiveOpener => {
                        m[..30].copy_from_slice("TSPPv1 active opener signature".as_bytes());
                        m[30] = 0x00; // pad
                        m[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length
                    },
                    TsppRole::PassiveOpener => {
                        m[..31].copy_from_slice("TSPPv1 passive opener signature".as_bytes());
                        m[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length
                    }
                }

                self.context_hash
                    .update(&fb[..f])
                    .map_err(TsppError::from_crypto_error)?
                    .digest(&mut m[32..])
                    .map_err(TsppError::from_crypto_error)?;

                Ed25519::sign_oneshot(&self.au_privkey_buf[..Ed25519::PRIVATE_KEY_LEN], &m[..],
                    &mut frag.au_signature[..Ed25519::SIGNATURE_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                self.context_hash
                    .update(&frag.au_signature[..Ed25519::SIGNATURE_LEN])
                    .map_err(TsppError::from_crypto_error)?;

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        }

        frag.to_bytes(&mut buf[..])?;

        self.state = TsppState::HelloSent;

        return Ok((s, self.state));

    }

    fn recv_hello(&mut self, buf: &[u8]) -> Result<(usize, TsppState), TsppError> {

        if !self.state.can_recv_hello(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let f: HelloFragment = HelloFragment::from_bytes(buf)?;

        if f.base.frag_type != FragmentType::Hello {
            return Err(TsppError::new(TsppErrorCode::IllegalFragment));
        }

        if f.version != self.version {
            return Err(TsppError::new(TsppErrorCode::VersionUnmatched));
        }

        if f.cipher_suite != self.cipher_suite {
            return Err(TsppError::new(TsppErrorCode::CipherSuiteUnmatched));
        }

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let r: usize = f.len();

        self.context_hash
            .update(&buf[..(r - c.au_signature_len)])
            .map_err(TsppError::from_crypto_error)?;

        match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let v = TsppEngine::is_known_peer_auth_public_key(
                    DigitalSignatureAlgorithm::Ed25519,
                    &f.au_pubkey[..Ed25519::PUBLIC_KEY_LEN]
                );

                // error handle
                println!("{}", v);

                let mut b: [u8; 32 + Sha3256::MESSAGE_DIGEST_LEN] = [0; 32 + Sha3256::MESSAGE_DIGEST_LEN];
                match self.role {
                    TsppRole::ActiveOpener => {
                        b[..31].copy_from_slice("TSPPv1 passive opener signature".as_bytes());
                        b[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length
                    },
                    TsppRole::PassiveOpener => {
                        b[..30].copy_from_slice("TSPPv1 active opener signature".as_bytes());
                        b[30] = 0x00; // pad
                        b[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length
                    }
                }

                self.context_hash
                    .digest(&mut b[32..])
                    .map_err(TsppError::from_crypto_error)?;

                for i in &buf[(r - Ed25519::SIGNATURE_LEN)..r] {
                    print!("{:02x}", i);
                }
                println!();
                for i in 0..b.len() {
                    print!("{:02x}", b[i]);
                }
                println!();

                let v: bool = Ed25519::verify_oneshot(&f.au_pubkey[..Ed25519::PUBLIC_KEY_LEN], &b[..],
                    &buf[(r - Ed25519::SIGNATURE_LEN)..r])
                    .map_err(TsppError::from_crypto_error)?;

                // error handle
                println!("{}", v);

                let mut s: [u8; X25519::SHARED_SECRET_LEN] = [0; X25519::SHARED_SECRET_LEN];
                X25519::compute_shared_secret_oneshot(&self.ke_privkey_buf[..X25519::PRIVATE_KEY_LEN],
                    &f.ke_pubkey[..X25519::PUBLIC_KEY_LEN], &mut s[..])
                    .map_err(TsppError::from_crypto_error)?;

                Sha3256::digest_oneshot(&s[..], &mut self.secret_buf[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                for i in &self.secret_buf[..c.current_secret_len] {
                    print!("{:02x}", i);
                }
                println!();

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        }

        self.context_hash
            .update(&buf[(r - c.au_signature_len)..r])
            .map_err(TsppError::from_crypto_error)?;

        self.state = TsppState::HelloRecvd;

        return Ok((r, self.state));

    }

    fn send_hello_done(&mut self, buf: &mut [u8]) -> Result<(usize, TsppState), TsppError> {

        if !self.state.can_send_hello_done(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let s: usize = FragmentBaseFields::BYTES_NUM + c.hash_msg_dgst_len;

        let mut frag: HelloDoneFragment = HelloDoneFragment{
            base: FragmentBaseFields{
                frag_type: FragmentType::HelloDone,
                reserved: 0x00,
                length: (s - FragmentBaseFields::BYTES_NUM) as u16
            },
            hello_phase_vrf_mac: [0; MAX_MESSAGE_DIGEST_LEN]
        };

        match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let mut k: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                HmacSha3256::compute_oneshot(&self.secret_buf[..HmacSha3256::MAC_LEN],
                    "TSPPv1 hello phase vrf mac key".as_bytes(), &mut k[..])
                    .map_err(TsppError::from_crypto_error)?;

                let mut d: [u8; Sha3256::MESSAGE_DIGEST_LEN] = [0; Sha3256::MESSAGE_DIGEST_LEN];
                self.context_hash.digest(&mut d[..]).map_err(TsppError::from_crypto_error)?;

                HmacSha3256::compute_oneshot(&k[..], &d[..],
                    &mut frag.hello_phase_vrf_mac[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?;

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        }

        frag.to_bytes(&mut buf[..])?;

        self.state = TsppState::HelloDoneSent;

        return Ok((s, self.state));

    }

    fn recv_hello_done(&mut self, buf: &[u8]) -> Result<(usize, TsppState), TsppError> {

        // let h: HelloDoneFragment = HelloDoneFragment::from_bytes(buf)?;

        self.state = TsppState::HelloDoneRecvd;

        return Ok((0, self.state));

    }

    fn set_hello_phase_secret(&mut self) -> Result<(), TsppError> {
        return match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let mut k: [u8; 32 + Sha3256::MESSAGE_DIGEST_LEN] = [0; 32 + Sha3256::MESSAGE_DIGEST_LEN];
                k[..25].copy_from_slice("TSPPv1 hello phase secret".as_bytes());
                k[25] = 0x00; // pad
                k[26] = 0x00; // pad
                k[27] = 0x00; // pad
                k[28] = 0x00; // pad
                k[29] = 0x00; // pad
                k[30] = 0x00; // pad
                k[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length

                self.context_hash
                    .digest(&mut k[32..])
                    .map_err(TsppError::from_crypto_error)?;

                HmacSha3256::new(&k[..])
                    .map_err(TsppError::from_crypto_error)?
                    .update(&self.secret_buf[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?
                    .compute(&mut self.secret_buf[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                let mut t: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                let (k1, n1, k2, n2): (&str, &str, &str, &str) = match self.role {
                    TsppRole::ActiveOpener => (
                        "active opener write key",
                        "active opener write iv",
                        "passive opener write key",
                        "passive opener write iv",
                    ),
                    TsppRole::PassiveOpener => (
                        "passive opener write key",
                        "passive opener write iv",
                        "active opener write key",
                        "active opener write iv",
                    ),
                };

                HmacSha3256::compute_oneshot(&self.secret_buf[..HmacSha3256::MAC_LEN],
                    k1.as_bytes(), &mut t[..])
                    .map_err(TsppError::from_crypto_error)?;
                self.send_aead.rekey(&t[..Aes128Gcm::KEY_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                HmacSha3256::compute_oneshot(&self.secret_buf[..HmacSha3256::MAC_LEN],
                    n1.as_bytes(), &mut t[..])
                    .map_err(TsppError::from_crypto_error)?;
                self.send_aead_iv
                    .copy_from_slice(&t[..Aes128Gcm::KEY_LEN]);

                HmacSha3256::compute_oneshot(&self.secret_buf[..HmacSha3256::MAC_LEN],
                    k2.as_bytes(), &mut t[..])
                    .map_err(TsppError::from_crypto_error)?;
                self.recv_aead.rekey(&t[..Aes128Gcm::KEY_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                HmacSha3256::compute_oneshot(&self.secret_buf[..HmacSha3256::MAC_LEN],
                    n2.as_bytes(), &mut t[..])
                    .map_err(TsppError::from_crypto_error)?;
                self.recv_aead_iv
                    .copy_from_slice(&t[..Aes128Gcm::KEY_LEN]);

                for i in &self.secret_buf[..HmacSha3256::MAC_LEN] {
                    print!("{:02x}", i);
                }
                println!();

                Ok(())

            },
            _ => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };
    }

    fn set_initial_user_stream_secret(&mut self) -> Result<(), TsppError> {
        return match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let mut k: [u8; 32 + Sha3256::MESSAGE_DIGEST_LEN] = [0; 32 + Sha3256::MESSAGE_DIGEST_LEN];
                k[..25].copy_from_slice("TSPPv1 user stream secret".as_bytes());
                k[25] = 0x00; // pad
                k[26] = 0x00; // pad
                k[27] = 0x00; // pad
                k[28] = 0x00; // pad
                k[29] = 0x00; // pad
                k[30] = 0x00; // pad
                k[31] = (32 + Sha3256::MESSAGE_DIGEST_LEN) as u8; // length

                self.context_hash
                    .digest(&mut k[32..])
                    .map_err(TsppError::from_crypto_error)?;

                HmacSha3256::new(&k[..])
                    .map_err(TsppError::from_crypto_error)?
                    .update(&self.secret_buf[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?
                    .compute(&mut self.secret_buf[..HmacSha3256::MAC_LEN])
                    .map_err(TsppError::from_crypto_error)?;

                Ok(())

            },
            _ => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };
    }

}






struct HelloDoneFragment {
    base: FragmentBaseFields,
    hello_phase_vrf_mac: [u8; MAX_MESSAGE_DIGEST_LEN] // # length can be derived from known.cipher_suite
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
    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> where Self: Sized;
    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError>;
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

    fn from_u8(u: u8) -> Result<Self, TsppError> {
        return match u {
            0x00 => Ok(Self::Hello),
            0x01 => Ok(Self::HelloDone),
            0x02 => Ok(Self::UserStream),
            0x03 => Ok(Self::Finish),
            0x04 => Ok(Self::KeyUpdate),
            0x05 => Ok(Self::HelloRetryRequest),
            0x06 => Ok(Self::HelloRetry),
            _    => Err(TsppError::new(TsppErrorCode::UnsupportedFragmentType))
        };
    }

    fn to_u8(&self) -> u8 {
        return *self as usize as u8;
    }

}

impl Clone for FragmentType {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for FragmentType {}

impl PartialEq for FragmentType {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for FragmentType {}

pub enum TsppVersion {
    Null     = 0x00000000,
    Version1 = 0x00000001,
}

impl TsppVersion {

    const BYTES_NUM: usize = 4;

    fn from_u32(u: u32) -> Result<Self, TsppError> {
        return match u {
            0x00000000 => Ok(Self::Null),
            0x00000001 => Ok(Self::Version1),
            _          => Err(TsppError::new(TsppErrorCode::UnsupportedVersion))
        };
    }

    fn to_u32(&self) -> u32 {
        return *self as usize as u32;
    }

    fn check_cipher_suite(&self, cipher_suite: TsppCipherSuite) -> bool {
        return match self {
            TsppVersion::Null     => false,
            TsppVersion::Version1 => match cipher_suite {
                TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => true,
                _                                                    => false
            },
        };
    }

}

impl Clone for TsppVersion {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for TsppVersion {}

impl PartialEq for TsppVersion {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for TsppVersion {}

impl Serializable for TsppVersion {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        return Self::from_u32(
            ((buf[0] as u32) << 24) |
            ((buf[1] as u32) << 16) |
            ((buf[2] as u32) <<  8) |
             (buf[3] as u32)
        );

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let u: u32 = self.to_u32();
        buf[0] = (u >> 24) as u8;
        buf[1] = (u >> 16) as u8;
        buf[2] = (u >>  8) as u8;
        buf[3] =  u        as u8;

        return Ok(());

    }

}

#[allow(non_camel_case_types)]
pub enum TsppCipherSuite {
    NULL_NULL_NULL_NULL                 = 0x0000000000000000,
    X25519_Ed25519_AES_128_GCM_SHA3_256 = 0x0000000000000001,
}

impl TsppCipherSuite {

    const BYTES_NUM: usize = 8;

    fn from_u64(u: u64) -> Result<Self, TsppError> {
        return match u {
            0x0000000000000000 => Ok(Self::NULL_NULL_NULL_NULL),
            0x0000000000000001 => Ok(Self::X25519_Ed25519_AES_128_GCM_SHA3_256),
            _                  => Err(TsppError::new(TsppErrorCode::UnsupportedCipherSuite))
        };
    }

    fn to_u64(&self) -> u64 {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => 0x0000000000000000,
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => 0x0000000000000001,
        };
    }

}

impl Clone for TsppCipherSuite {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for TsppCipherSuite {}

impl PartialEq for TsppCipherSuite {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for TsppCipherSuite {}

impl Serializable for TsppCipherSuite {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
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

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
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

        return Ok(());

    }

}

struct FragmentBaseFields {
    frag_type: FragmentType,
    reserved: u8,
    length: u16, // # length of subsequent part
}

impl FragmentBaseFields {
    const BYTES_NUM: usize = 4;
}

impl Serializable for FragmentBaseFields {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        return Ok(Self{
            frag_type: FragmentType::from_u8(buf[0])?,
            reserved: buf[1],
            length: ((buf[2] as u16) << 8) | (buf[3] as u16)
        });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        if buf.len() < Self::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        buf[0] = self.frag_type.to_u8();
        buf[1] = self.reserved;
        buf[2] = (self.length >> 8) as u8;
        buf[3] = self.length as u8;

        return Ok(());

    }

}

struct HelloFragment {
    base: FragmentBaseFields,
    version: TsppVersion,
    cipher_suite: TsppCipherSuite,
    random: [u8; 64],
    ke_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_signature: [u8; 64] // # length can be derived from self.cipher_suite
}

impl HelloFragment {

    pub fn len(&self) -> usize {
        return FragmentBaseFields::BYTES_NUM + (self.base.length as usize);
    }

}

impl Serializable for HelloFragment {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        let len: usize =
            FragmentBaseFields::BYTES_NUM +
            TsppVersion::BYTES_NUM +
            TsppCipherSuite::BYTES_NUM +
            64;
        if buf.len() < len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let cipher_suite: TsppCipherSuite = TsppCipherSuite::from_bytes(&buf[8..])?;
        let c: CipherSuiteConstants = cipher_suite.constants();

        let len: usize = len + c.ke_pubkey_len + c.au_pubkey_len + c.au_signature_len;
        if buf.len() < len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let mut v: Self = Self{
            base: FragmentBaseFields::from_bytes(&buf[..])?,
            version: TsppVersion::from_bytes(&buf[4..])?,
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

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let len: usize =
            FragmentBaseFields::BYTES_NUM +
            TsppVersion::BYTES_NUM +
            TsppCipherSuite::BYTES_NUM +
            64 +
            c.ke_pubkey_len +
            c.au_pubkey_len +
            c.au_signature_len;

        if buf.len() < len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
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

        return Ok(());

    }

}









impl Serializable for HelloDoneFragment {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < FragmentBaseFields::BYTES_NUM {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let base: FragmentBaseFields = FragmentBaseFields::from_bytes(&buf[..])?;
        let mac_len: usize = base.length as usize;
        let overall_len: usize = FragmentBaseFields::BYTES_NUM + mac_len;

        if buf.len() < overall_len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let mut v: Self = Self{
            base: base,
            hello_phase_vrf_mac: [0; MAX_MESSAGE_DIGEST_LEN]
        };

        v.hello_phase_vrf_mac[..mac_len]
            .copy_from_slice(&buf[FragmentBaseFields::BYTES_NUM..overall_len]);

        return Ok(v);

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        let mac_len: usize = self.base.length as usize;
        let overall_len: usize = FragmentBaseFields::BYTES_NUM + mac_len;

        if buf.len() < overall_len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        self.base.to_bytes(&mut buf[..]).unwrap();
        buf[FragmentBaseFields::BYTES_NUM..overall_len]
            .copy_from_slice(&self.hello_phase_vrf_mac[..mac_len]);

        return Ok(());

    }

}

struct CipherSuiteConstants {
    ke_privkey_len: usize,
    ke_pubkey_len: usize,
    ke_shared_secret_len: usize,
    au_privkey_len: usize,
    au_pubkey_len: usize,
    au_signature_len: usize,
    current_secret_len: usize,
    aead_key_len: usize,
    aead_tag_len: usize,
    hash_msg_dgst_len: usize
}

impl TsppCipherSuite {

    fn constants(&self) -> CipherSuiteConstants {
        return match self {
            Self::NULL_NULL_NULL_NULL => CipherSuiteConstants{
                ke_privkey_len: 0,
                ke_pubkey_len: 0,
                ke_shared_secret_len: 0,
                au_privkey_len: 0,
                au_pubkey_len: 0,
                au_signature_len: 0,
                current_secret_len: 0,
                aead_key_len: 0,
                aead_tag_len: 0,
                hash_msg_dgst_len: 0
            },
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => CipherSuiteConstants{
                ke_privkey_len: X25519::PRIVATE_KEY_LEN,
                ke_pubkey_len: X25519::PUBLIC_KEY_LEN,
                ke_shared_secret_len: X25519::SHARED_SECRET_LEN,
                au_privkey_len: Ed25519::PRIVATE_KEY_LEN,
                au_pubkey_len: Ed25519::PUBLIC_KEY_LEN,
                au_signature_len: Ed25519::SIGNATURE_LEN,
                current_secret_len: HmacSha3256::MAC_LEN,
                aead_key_len: Aes128Gcm::KEY_LEN,
                aead_tag_len: Aes128Gcm::TAG_LEN,
                hash_msg_dgst_len: Sha3256::MESSAGE_DIGEST_LEN
            },
        };
    }

    fn hash(&self) -> Result<Hash, TsppError> {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite)),
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => Ok(Hash::new(HashAlgorithm::Sha3256)),
        };
    }

    fn aead(&self, key: &[u8]) -> Result<Aead, TsppError> {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite)),
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => Ok(Aead::new(AeadAlgorithm::Aes128Gcm, key).map_err(TsppError::from_crypto_error)?),
        };
    }

}