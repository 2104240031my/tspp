use cryptopkg::crypto::feature::Aead as AeadFeature;
use cryptopkg::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use cryptopkg::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use cryptopkg::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use cryptopkg::crypto::feature::Hash as HashFeature;
use cryptopkg::crypto::feature::Mac as MacFeature;
use cryptopkg::crypto::aes_aead::Aes128Gcm;
use cryptopkg::crypto::ed25519::Ed25519;
use cryptopkg::crypto::ed25519::Ed25519Signer;
use cryptopkg::crypto::ed25519::Ed25519Verifier;
use cryptopkg::crypto::hmac_sha3::HmacSha3256;
use cryptopkg::crypto::sha3::Sha3256;
use cryptopkg::crypto::x25519::X25519;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use crate::net::crypto::Aead;
use crate::net::crypto::AeadAlgorithm;
use crate::net::crypto::DiffieHellmanAlgorithm;
use crate::net::crypto::DigitalSignatureAlgorithm;
use crate::net::crypto::DigitalSignatureSigner;
use crate::net::crypto::DigitalSignatureVerifier;
use crate::net::crypto::Hash;
use crate::net::crypto::HashAlgorithm;
use crate::net::crypto::constant_time_eq;
use crate::net::error::TsppError;
use crate::net::error::TsppErrorCode;

const MAX_KE_PRIVATE_KEY_LEN: usize      = X25519::PRIVATE_KEY_LEN;
const MAX_KE_PUBLIC_KEY_LEN: usize       = X25519::PUBLIC_KEY_LEN;
const MAX_CURRENT_SECRET_LEN: usize      = HmacSha3256::MAC_LEN;
const MAX_AU_PRIVATE_KEY_LEN: usize      = Ed25519::PRIVATE_KEY_LEN;
const MAX_AU_PUBLIC_KEY_LEN: usize       = Ed25519::PUBLIC_KEY_LEN;
const MAX_AEAD_KEY_LEN: usize            = Aes128Gcm::KEY_LEN;
const MAX_AEAD_NONCE_LEN: usize          = Aes128Gcm::MAX_NONCE_LEN;
const MAX_AEAD_TAG_LEN: usize            = Aes128Gcm::TAG_LEN;
const MAX_HASH_MESSAGE_DIGEST_LEN: usize = Sha3256::MESSAGE_DIGEST_LEN;

pub struct TsppSocket {
    state: State,
    version: TsppVersion,
    cipher_suite: TsppCipherSuite,
    role: TsppRole,
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

enum State {
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

pub enum TsppHelloPhaseState {
    InProgress,
    Done,
}


impl Clone for TsppHelloPhaseState {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for TsppHelloPhaseState {}

impl PartialEq for TsppHelloPhaseState {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for TsppHelloPhaseState {}

impl State {

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

    fn can_send_bye(&self) -> bool {
        return self.can_send_user_stream();
    }

    fn can_recv_bye(&self) -> bool {
        return self.can_recv_user_stream();
    }

}

impl Clone for State {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for State {}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool { return *self as usize == *other as usize; }
}

impl Eq for State {}

static ENGINE: LazyLock<Mutex<TsppEngine>> = LazyLock::new(|| Mutex::new(TsppEngine::new()));

pub struct TsppEngine {
    inner: HashMap<(usize, Vec<u8>), Vec<u8>>
}

impl TsppEngine {

    pub fn new() -> Self {
        return Self{ inner: HashMap::<(usize, Vec<u8>), Vec<u8>>::new() };
    }

    pub fn insert_known_peer_auth_public_key(algo: DigitalSignatureAlgorithm, pubkey: &[u8]) {
        ENGINE.lock().unwrap().inner.insert((algo as usize, pubkey.to_vec()), pubkey.to_vec());
    }

    pub fn is_known_peer_auth_public_key(algo: DigitalSignatureAlgorithm, pubkey: &[u8]) -> bool {
        return match ENGINE.lock().unwrap().inner.get(&(algo as usize, pubkey.to_vec())) {
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
            state: State::Initial,
            version: version,
            cipher_suite: cipher_suite,
            role: role,
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

    pub fn hello_phase_send(&mut self, buf: &mut [u8]) -> Result<(usize, TsppHelloPhaseState), TsppError> {
        return match self.role {
            TsppRole::ActiveOpener => match self.state {
                State::Initial        => Ok((self.send_hello(buf)?, TsppHelloPhaseState::InProgress)),
                State::HelloDoneRecvd => {
                    let s: usize = self.send_hello_done(buf)?;
                    self.set_initial_user_stream_secret()?;
                    Ok((s, TsppHelloPhaseState::Done))
                },
                State::BidiUserStream => Ok((0, TsppHelloPhaseState::Done)),
                _                     => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            },
            TsppRole::PassiveOpener => match self.state {
                State::HelloRecvd     => {
                    let s: usize = self.send_hello(buf)?;
                    self.set_hello_phase_secret()?;
                    Ok((s, TsppHelloPhaseState::InProgress))
                },
                State::HelloSent      => Ok((self.send_hello_done(buf)?, TsppHelloPhaseState::Done)),
                State::BidiUserStream => Ok((0, TsppHelloPhaseState::Done)),
                _                     => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            }
        };
    }

    pub fn hello_phase_recv(&mut self, buf: &mut [u8]) -> Result<(usize, TsppHelloPhaseState), TsppError> {
        return match self.role {
            TsppRole::ActiveOpener => match self.state {
                State::HelloSent      => {
                    let r: usize = self.recv_hello(buf)?;
                    self.set_hello_phase_secret()?;
                    Ok((r, TsppHelloPhaseState::InProgress))
                },
                State::HelloRecvd     => Ok((self.recv_hello_done(buf)?, TsppHelloPhaseState::InProgress)),
                State::BidiUserStream => Ok((0, TsppHelloPhaseState::Done)),
                _                     => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            },
            TsppRole::PassiveOpener => match self.state {
                State::Initial        => Ok((self.recv_hello(buf)?, TsppHelloPhaseState::InProgress)),
                State::HelloDoneSent  => {
                    let r: usize = self.recv_hello_done(buf)?;
                    self.set_initial_user_stream_secret()?;
                    Ok((r, TsppHelloPhaseState::Done))
                },
                State::BidiUserStream => Ok((0, TsppHelloPhaseState::Done)),
                _                     => Err(TsppError::new(TsppErrorCode::UnsuitableState))
            }
        };
    }

    pub fn send(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(usize, usize), TsppError> {

        if !self.state.can_send_user_stream() {
            return Err(TsppError::new(TsppErrorCode::UserStreamIsNotReady));
        }

        let tag_len: usize = self.cipher_suite.constants().aead_tag_len;

        let mut i_off: usize = 0;
        let mut o_off: usize = 0;
        let i_cap: usize = in_buf.len();
        let o_cap: usize = out_buf.len();
        let mut read: usize = 0;
        let mut written: usize = 0;
        loop {

            let i_len: usize = i_cap - i_off;
            let o_len: usize = o_cap - o_off;

            if i_len == 0 || o_len == 0 {
                break;
            }

            if o_len < FragmentHeader::BYTES_LEN + tag_len {
                break;
            }

            let payload_len: usize = {
                let p: usize = if i_len < 0xffff { i_len } else { 0xffff };
                if o_len < FragmentHeader::BYTES_LEN + p + tag_len { o_len } else { p }
            };
            let fragment_len: usize = FragmentHeader::BYTES_LEN + payload_len + tag_len;

            let mut hdr: [u8; FragmentHeader::BYTES_LEN] = [0; FragmentHeader::BYTES_LEN];
            FragmentHeader::make_bytes_into(FragmentType::UserStream, 0x00, payload_len, &mut hdr[..])?;

            let o1: usize = o_off + FragmentHeader::BYTES_LEN;
            let o2: usize = o1 + payload_len;
            let o3: usize = o2 + tag_len;

            let mut tag: [u8; MAX_AEAD_TAG_LEN] = [0; MAX_AEAD_TAG_LEN];
            self.aead_seal(
                &hdr[..],
                &in_buf[i_off..(i_off + payload_len)],
                &mut out_buf[o1..o2],
                &mut tag[..tag_len]
            )?;

            out_buf[o_off..o1].copy_from_slice(&hdr[..]);
            out_buf[o2..o3].copy_from_slice(&tag[..tag_len]);

            i_off = i_off + payload_len;
            o_off = o_off + fragment_len;

            read = read + payload_len;
            written = written + fragment_len;

        }

        return Ok((read, written));

    }

    pub fn recv(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(usize, usize), TsppError> {

        if !self.state.can_recv_user_stream() {
            return Err(if self.state == State::ByeRecvd {
                TsppError::new(TsppErrorCode::ByeFragmentRecvd)
            } else {
                TsppError::new(TsppErrorCode::UserStreamIsNotReady)
            });
        }

        let tag_len: usize = self.cipher_suite.constants().aead_tag_len;

        let mut i_off: usize = 0;
        let mut o_off: usize = 0;
        let i_cap: usize = in_buf.len();
        let o_cap: usize = out_buf.len();
        let mut read: usize = 0;
        let mut written: usize = 0;
        loop {

            let i_len: usize = i_cap - i_off;
            let o_len: usize = o_cap - o_off;

            if i_len == 0 || o_len == 0 {
                break;
            }

            if i_len < FragmentHeader::BYTES_LEN + tag_len {
                break;
            }

            let hdr: FragmentHeader = FragmentHeader::make(&in_buf[i_off..])?;
            if hdr.frag_type != FragmentType::UserStream {
                if hdr.frag_type == FragmentType::Bye {
                    read = read + self.recv_bye(&in_buf[i_off..])?;
                    break;
                }
                return Err(TsppError::new(TsppErrorCode::IllegalFragment));
            }

            let payload_len: usize = hdr.length as usize;
            let fragment_len: usize = FragmentHeader::BYTES_LEN + payload_len + tag_len;

            if i_len < fragment_len || o_len < payload_len {
                break;
            }

            let i1: usize = i_off + FragmentHeader::BYTES_LEN;
            let i2: usize = i1 + payload_len;

            match self.aead_open(
                &in_buf[i_off..i1],
                &in_buf[i1..i2],
                &mut out_buf[o_off..(o_off + payload_len)],
                &in_buf[i2..(i2 + tag_len)]
            ) {
                // ERROR!: must be send by or finish stream
                Ok(v)  => if !v { return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed)); },
                Err(_) => return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed))
            };

            i_off = i_off + fragment_len;
            o_off = o_off + payload_len;

            read = read + fragment_len;
            written = written + payload_len;

        }

        return Ok((read, written));

    }

    pub fn send_bye(&mut self, buf: &mut [u8]) -> Result<usize, TsppError> {

        if !self.state.can_send_bye() {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let tag_len: usize = self.cipher_suite.constants().aead_tag_len;
        let s: usize = FragmentHeader::BYTES_LEN + tag_len;

        let mut hdr: [u8; FragmentHeader::BYTES_LEN] = [0; FragmentHeader::BYTES_LEN];
        FragmentHeader::make_bytes_into(FragmentType::Bye, 0x00, 0, &mut hdr[..])?;

        buf[..FragmentHeader::BYTES_LEN].copy_from_slice(&hdr[..]);
        self.aead_seal(&hdr[..], &[], &mut [], &mut buf[FragmentHeader::BYTES_LEN..s])?;

        self.state = match self.state {
            State::BidiUserStream => State::ByeSent,
            State::ByeRecvd       => State::Closed,
            _                         => {
                return Err(TsppError::new(TsppErrorCode::UnsuitableState));
            }
        };
        return Ok(s);

    }

    fn send_hello(&mut self, buf: &mut [u8]) -> Result<usize, TsppError> {

        if !self.state.can_send_hello(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let c: CipherSuiteConstants = self.cipher_suite.constants();
        let s: usize =
            FragmentHeader::BYTES_LEN +
            TsppVersion::BYTES_LEN +
            TsppCipherSuite::BYTES_LEN +
            64 +
            c.ke_pubkey_len +
            c.au_pubkey_len +
            c.au_signature_len;

        let mut frag: HelloFragment = HelloFragment{
            base: FragmentHeader{
                frag_type: FragmentType::Hello,
                reserved: 0x00,
                length: (s - FragmentHeader::BYTES_LEN) as u16
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

                X25519::compute_public_key_oneshot(
                    &self.ke_privkey_buf[..X25519::PRIVATE_KEY_LEN],
                    &mut frag.ke_pubkey[..X25519::PUBLIC_KEY_LEN]
                )?;

                Ed25519Signer::compute_public_key_oneshot(
                    &self.au_privkey_buf[..Ed25519::PRIVATE_KEY_LEN],
                    &mut frag.au_pubkey[..Ed25519::PUBLIC_KEY_LEN]
                )?;

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

                self.context_hash.update(&fb[..f])?.digest(&mut m[32..])?;

                Ed25519Signer::sign_oneshot(
                    &self.au_privkey_buf[..Ed25519::PRIVATE_KEY_LEN],
                    &m[..],
                    &mut frag.au_signature[..Ed25519::SIGNATURE_LEN]
                )?;

                self.context_hash.update(&frag.au_signature[..Ed25519::SIGNATURE_LEN])?;

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        }

        frag.to_bytes(&mut buf[..])?;

        self.state = State::HelloSent;
        return Ok(s);

    }

    fn recv_hello(&mut self, buf: &[u8]) -> Result<usize, TsppError> {

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

        self.context_hash.update(&buf[..(r - c.au_signature_len)])?;

        match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                if f.base.length as usize != 76 + X25519::PUBLIC_KEY_LEN + Ed25519::PUBLIC_KEY_LEN + Ed25519::SIGNATURE_LEN {
                    return Err(TsppError::new(TsppErrorCode::IllegalFragment));
                }

                if !TsppEngine::is_known_peer_auth_public_key(
                    DigitalSignatureAlgorithm::Ed25519,
                    &f.au_pubkey[..Ed25519::PUBLIC_KEY_LEN]
                ) {
                    // ERROR!: must be send by or finish stream
                    return Err(TsppError::new(TsppErrorCode::UnknownAuPublicKey));
                };

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

                self.context_hash.digest(&mut b[32..])?;

                if !Ed25519Verifier::verify_oneshot(
                    &f.au_pubkey[..Ed25519::PUBLIC_KEY_LEN],
                    &b[..],
                    &buf[(r - Ed25519::SIGNATURE_LEN)..r]
                )? {
                    // ERROR!: must be send by or finish stream
                    return Err(TsppError::new(TsppErrorCode::PeerAuthFailed));
                }

                let mut s: [u8; X25519::SHARED_SECRET_LEN] = [0; X25519::SHARED_SECRET_LEN];
                X25519::compute_shared_secret_oneshot(
                    &self.ke_privkey_buf[..X25519::PRIVATE_KEY_LEN],
                    &f.ke_pubkey[..X25519::PUBLIC_KEY_LEN],
                    &mut s[..]
                )?;

                Sha3256::digest_oneshot(&s[..], &mut self.secret_buf[..HmacSha3256::MAC_LEN])?;

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        }

        self.context_hash.update(&buf[(r - c.au_signature_len)..r])?;

        self.state = State::HelloRecvd;
        return Ok(r);

    }

    fn send_hello_done(&mut self, buf: &mut [u8]) -> Result<usize, TsppError> {

        if !self.state.can_send_hello_done(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let s: usize = match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let s: usize = FragmentHeader::BYTES_LEN + HmacSha3256::MAC_LEN + Aes128Gcm::TAG_LEN;

                let hdr: [u8; FragmentHeader::BYTES_LEN] = FragmentHeader::make_bytes(
                    FragmentType::HelloDone,
                    0x00,
                    HmacSha3256::MAC_LEN
                )?;

                let mut k: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                HmacSha3256::compute_oneshot(
                    &self.secret_buf[..HmacSha3256::MAC_LEN],
                    "TSPPv1 hello phase vrf mac key".as_bytes(),
                    &mut k[..]
                )?;

                let mut d: [u8; Sha3256::MESSAGE_DIGEST_LEN] = [0; Sha3256::MESSAGE_DIGEST_LEN];
                self.context_hash.digest(&mut d[..])?;

                let mut mac: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                HmacSha3256::compute_oneshot(&k[..], &d[..], &mut mac[..])?;

                self.context_hash.update(&hdr[..])?.update(&mac[..])?;

                let mut tag: [u8; Aes128Gcm::TAG_LEN] = [0; Aes128Gcm::TAG_LEN];
                self.aead_seal(
                    &hdr[..],
                    &mac[..],
                    &mut buf[FragmentHeader::BYTES_LEN..(FragmentHeader::BYTES_LEN + HmacSha3256::MAC_LEN)],
                    &mut tag[..]
                )?;

                buf[..FragmentHeader::BYTES_LEN].copy_from_slice(&hdr[..]);
                buf[(s - Aes128Gcm::TAG_LEN)..s].copy_from_slice(&tag[..]);

                s

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };

        self.state = match self.role {
            TsppRole::ActiveOpener  => State::BidiUserStream,
            TsppRole::PassiveOpener => State::HelloDoneSent
        };
        return Ok(s);

    }

    fn recv_hello_done(&mut self, buf: &mut [u8]) -> Result<usize, TsppError> {

        if !self.state.can_recv_hello_done(self.role) {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let hdr: FragmentHeader = FragmentHeader::make(&buf[..])?;
        if hdr.frag_type != FragmentType::HelloDone {
            return Err(TsppError::new(TsppErrorCode::IllegalFragment));
        }

        let r: usize = match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {

                let r: usize = FragmentHeader::BYTES_LEN + HmacSha3256::MAC_LEN + Aes128Gcm::TAG_LEN;
                if buf.len() < r {
                    return Err(TsppError::new(TsppErrorCode::BufferTooShort));
                }

                if hdr.length as usize != HmacSha3256::MAC_LEN {
                    return Err(TsppError::new(TsppErrorCode::IllegalFragment));
                }

                let mut mac: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];

                match self.aead_open(
                    &buf[..FragmentHeader::BYTES_LEN],
                    &buf[FragmentHeader::BYTES_LEN..(FragmentHeader::BYTES_LEN + HmacSha3256::MAC_LEN)],
                    &mut mac[..],
                    &buf[(r - Aes128Gcm::TAG_LEN)..r]
                ) {
                    // ERROR!: must be send by or finish stream
                    Ok(v)  => if !v { return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed)); },
                    Err(_) => return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed))
                };

                let mut k: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                HmacSha3256::compute_oneshot(
                    &self.secret_buf[..HmacSha3256::MAC_LEN],
                    "TSPPv1 hello phase vrf mac key".as_bytes(),
                    &mut k[..]
                )?;

                let mut d: [u8; Sha3256::MESSAGE_DIGEST_LEN] = [0; Sha3256::MESSAGE_DIGEST_LEN];
                self.context_hash.digest(&mut d[..])?;

                let mut mac_v: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                HmacSha3256::compute_oneshot(
                    &k[..],
                    &d[..],
                    &mut mac_v[..]
                )?;

                if !constant_time_eq(&mac[..], &mac_v[..]) {
                    // ERROR!: must be send by or finish stream
                    return Err(TsppError::new(TsppErrorCode::HelloPhaseVerificationFailed));
                }

                self.context_hash.update(&buf[..FragmentHeader::BYTES_LEN])?.update(&mac[..])?;

                r

            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };

        self.state = match self.role {
            TsppRole::ActiveOpener  => State::HelloDoneRecvd,
            TsppRole::PassiveOpener => State::BidiUserStream
        };
        return Ok(r);

    }

    fn recv_bye(&mut self, buf: &[u8]) -> Result<usize, TsppError> {

        if !self.state.can_recv_bye() {
            return Err(TsppError::new(TsppErrorCode::UnsuitableState));
        }

        let tag_len: usize = self.cipher_suite.constants().aead_tag_len;
        let r: usize = FragmentHeader::BYTES_LEN + tag_len;
        if buf.len() < r {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let hdr: FragmentHeader = FragmentHeader::make(&buf[..])?;
        if hdr.frag_type != FragmentType::Bye || hdr.length as usize != 0 {
            return Err(TsppError::new(TsppErrorCode::IllegalFragment));
        }

        match self.aead_open(
            &buf[..FragmentHeader::BYTES_LEN],
            &[],
            &mut [],
            &buf[FragmentHeader::BYTES_LEN..r]
        ) {
            // ERROR!: must be send by or finish stream
            Ok(v)  => if !v { return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed)); },
            Err(_) => return Err(TsppError::new(TsppErrorCode::AeadDecryptionFailed))
        };

        self.state = match self.state {
            State::BidiUserStream => State::ByeRecvd,
            State::ByeSent        => State::Closed,
            _                     => {
                return Err(TsppError::new(TsppErrorCode::UnsuitableState));
            }
        };
        return Ok(r);

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

                self.context_hash.digest(&mut k[32..])?;

                HmacSha3256::new(&k[..])?
                    .update(&self.secret_buf[..HmacSha3256::MAC_LEN])?
                    .compute(&mut self.secret_buf[..HmacSha3256::MAC_LEN])?;

                let mut t: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                let (s1, s2, r1, r2): (&str, &str, &str, &str) = match self.role {
                    TsppRole::ActiveOpener  => (
                        "active opener write key",
                        "active opener write iv",
                        "passive opener write key",
                        "passive opener write iv"
                    ),
                    TsppRole::PassiveOpener => (
                        "passive opener write key",
                        "passive opener write iv",
                        "active opener write key",
                        "active opener write iv"
                    )
                };

                let secret: &[u8] = &self.secret_buf[..HmacSha3256::MAC_LEN];

                HmacSha3256::compute_oneshot(secret, s1.as_bytes(), &mut t[..])?;
                self.send_aead.rekey(&t[..Aes128Gcm::KEY_LEN])?;

                HmacSha3256::compute_oneshot(secret, s2.as_bytes(), &mut t[..])?;
                self.send_aead_iv.copy_from_slice(&t[..Aes128Gcm::MAX_NONCE_LEN]);

                HmacSha3256::compute_oneshot(secret, r1.as_bytes(), &mut t[..])?;
                self.recv_aead.rekey(&t[..Aes128Gcm::KEY_LEN])?;

                HmacSha3256::compute_oneshot(secret, r2.as_bytes(), &mut t[..])?;
                self.recv_aead_iv.copy_from_slice(&t[..Aes128Gcm::MAX_NONCE_LEN]);

                self.send_frag_ctr = 0;
                self.recv_frag_ctr = 0;

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

                self.context_hash.digest(&mut k[32..])?;

                HmacSha3256::new(&k[..])?
                    .update(&self.secret_buf[..HmacSha3256::MAC_LEN])?
                    .compute(&mut self.secret_buf[..HmacSha3256::MAC_LEN])?;

                let mut t: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
                let (s1, s2, r1, r2): (&str, &str, &str, &str) = match self.role {
                    TsppRole::ActiveOpener  => (
                        "active opener write key",
                        "active opener write iv",
                        "passive opener write key",
                        "passive opener write iv"
                    ),
                    TsppRole::PassiveOpener => (
                        "passive opener write key",
                        "passive opener write iv",
                        "active opener write key",
                        "active opener write iv"
                    )
                };

                let secret: &[u8] = &self.secret_buf[..HmacSha3256::MAC_LEN];

                HmacSha3256::compute_oneshot(secret, s1.as_bytes(), &mut t[..])?;
                self.send_aead.rekey(&t[..Aes128Gcm::KEY_LEN])?;

                HmacSha3256::compute_oneshot(secret, s2.as_bytes(), &mut t[..])?;
                self.send_aead_iv.copy_from_slice(&t[..Aes128Gcm::MAX_NONCE_LEN]);

                HmacSha3256::compute_oneshot(secret, r1.as_bytes(), &mut t[..])?;
                self.recv_aead.rekey(&t[..Aes128Gcm::KEY_LEN])?;

                HmacSha3256::compute_oneshot(secret, r2.as_bytes(), &mut t[..])?;
                self.recv_aead_iv.copy_from_slice(&t[..Aes128Gcm::MAX_NONCE_LEN]);

                self.send_frag_ctr = 0;
                self.recv_frag_ctr = 0;

                Ok(())

            },
            _ => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };
    }

    fn aead_seal(&mut self, aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), TsppError> {

        let mut nonce: [u8; MAX_AEAD_NONCE_LEN] = [0; MAX_AEAD_NONCE_LEN];
        let ctr: [u8; 8] = self.send_frag_ctr.to_be_bytes();

        let nonce_len: usize = match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {
                nonce[0]  = self.send_aead_iv[0];
                nonce[1]  = self.send_aead_iv[1];
                nonce[2]  = self.send_aead_iv[2];
                nonce[3]  = self.send_aead_iv[3];
                nonce[4]  = self.send_aead_iv[4]  ^ ctr[0];
                nonce[5]  = self.send_aead_iv[5]  ^ ctr[1];
                nonce[6]  = self.send_aead_iv[6]  ^ ctr[2];
                nonce[7]  = self.send_aead_iv[7]  ^ ctr[3];
                nonce[8]  = self.send_aead_iv[8]  ^ ctr[4];
                nonce[9]  = self.send_aead_iv[9]  ^ ctr[5];
                nonce[10] = self.send_aead_iv[10] ^ ctr[6];
                nonce[11] = self.send_aead_iv[11] ^ ctr[7];
                12
            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };

        self.send_aead.encrypt_and_generate(
            &nonce[..nonce_len],
            aad,
            plaintext,
            ciphertext,
            tag
        )?;

        self.send_frag_ctr = self.send_frag_ctr + 1;
        return Ok(());

    }

    fn aead_open(&mut self, aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, TsppError> {

        let mut nonce: [u8; MAX_AEAD_NONCE_LEN] = [0; MAX_AEAD_NONCE_LEN];
        let ctr: [u8; 8] = self.recv_frag_ctr.to_be_bytes();

        let nonce_len: usize = match self.cipher_suite {
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256 => {
                nonce[0]  = self.recv_aead_iv[0];
                nonce[1]  = self.recv_aead_iv[1];
                nonce[2]  = self.recv_aead_iv[2];
                nonce[3]  = self.recv_aead_iv[3];
                nonce[4]  = self.recv_aead_iv[4]  ^ ctr[0];
                nonce[5]  = self.recv_aead_iv[5]  ^ ctr[1];
                nonce[6]  = self.recv_aead_iv[6]  ^ ctr[2];
                nonce[7]  = self.recv_aead_iv[7]  ^ ctr[3];
                nonce[8]  = self.recv_aead_iv[8]  ^ ctr[4];
                nonce[9]  = self.recv_aead_iv[9]  ^ ctr[5];
                nonce[10] = self.recv_aead_iv[10] ^ ctr[6];
                nonce[11] = self.recv_aead_iv[11] ^ ctr[7];
                12
            },
            _ => return Err(TsppError::new(TsppErrorCode::IllegalCipherSuite))
        };

        let v: bool = self.recv_aead.decrypt_and_verify(
            &nonce[..nonce_len],
            aad,
            ciphertext,
            plaintext,
            tag
        )?;

        self.recv_frag_ctr = self.recv_frag_ctr + 1;
        return Ok(v);

    }

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
    Bye               = 0x03,
    KeyUpdate         = 0x04,
    HelloRetryRequest = 0x05,
    HelloRetry        = 0x06,
}

impl FragmentType {

    const BYTES_LEN: usize = 4;

    fn from_u8(u: u8) -> Result<Self, TsppError> {
        return match u {
            0x00 => Ok(Self::Hello),
            0x01 => Ok(Self::HelloDone),
            0x02 => Ok(Self::UserStream),
            0x03 => Ok(Self::Bye),
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

    const BYTES_LEN: usize = 4;

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

        if buf.len() < Self::BYTES_LEN {
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

        if buf.len() < Self::BYTES_LEN {
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

    const BYTES_LEN: usize = 8;

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

        if buf.len() < Self::BYTES_LEN {
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

        if buf.len() < Self::BYTES_LEN {
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

struct FragmentHeader {
    frag_type: FragmentType,
    reserved: u8,
    length: u16, // # length of payload (i.e. overall length - (header length + tag length))
}

impl FragmentHeader {

    const BYTES_LEN: usize = 4;

    fn make(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        return Ok(Self{
            frag_type: FragmentType::from_u8(buf[0])?,
            reserved: buf[1],
            length: ((buf[2] as u16) << 8) | (buf[3] as u16)
        });

    }

    fn make_bytes(frag_type: FragmentType, reserved: u8,
        payload_len: usize) -> Result<[u8; Self::BYTES_LEN], TsppError> {

        // # integer overflow validation code
        // if payload_len > usize::MAX - tag_len {}

        if payload_len > 0xffff {
            return Err(TsppError::new(TsppErrorCode::IllegalArgument));
        }

        return Ok([frag_type as u8, reserved, (payload_len >> 8) as u8, payload_len as u8]);

    }

    fn make_bytes_into(frag_type: FragmentType, reserved: u8, payload_len: usize,
        buf: &mut [u8]) -> Result<(), TsppError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        // # integer overflow validation code
        // if payload_len > usize::MAX - tag_len {}

        if payload_len > 0xffff {
            return Err(TsppError::new(TsppErrorCode::IllegalArgument));
        }

        buf[0] = frag_type as u8;
        buf[1] = reserved;
        buf[2] = (payload_len >> 8) as u8;
        buf[3] = payload_len as u8;

        return Ok(());

    }

}

impl Serializable for FragmentHeader {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        return Ok(Self{
            frag_type: FragmentType::from_u8(buf[0])?,
            reserved: buf[1],
            length: ((buf[2] as u16) << 8) | (buf[3] as u16)
        });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        if buf.len() < Self::BYTES_LEN {
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
    base: FragmentHeader,
    version: TsppVersion,
    cipher_suite: TsppCipherSuite,
    random: [u8; 64],
    ke_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_pubkey: [u8; 32],   // # length can be derived from self.cipher_suite
    au_signature: [u8; 64] // # length can be derived from self.cipher_suite
}

impl HelloFragment {

    pub fn len(&self) -> usize {
        return FragmentHeader::BYTES_LEN + (self.base.length as usize);
    }

}

impl Serializable for HelloFragment {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        let len: usize =
            FragmentHeader::BYTES_LEN +
            TsppVersion::BYTES_LEN +
            TsppCipherSuite::BYTES_LEN +
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
            base: FragmentHeader::from_bytes(&buf[..])?,
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
            FragmentHeader::BYTES_LEN +
            TsppVersion::BYTES_LEN +
            TsppCipherSuite::BYTES_LEN +
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

struct HelloDoneFragment {
    base: FragmentHeader,
    hello_phase_vrf_mac: [u8; MAX_HASH_MESSAGE_DIGEST_LEN] // # length can be derived from known.cipher_suite
}

impl HelloDoneFragment {

    pub fn len(&self) -> usize {
        return FragmentHeader::BYTES_LEN + (self.base.length as usize);
    }

}

impl Serializable for HelloDoneFragment {

    fn from_bytes(buf: &[u8]) -> Result<Self, TsppError> {

        if buf.len() < FragmentHeader::BYTES_LEN {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let base: FragmentHeader = FragmentHeader::from_bytes(&buf[..])?;
        let mac_len: usize = base.length as usize;
        let overall_len: usize = FragmentHeader::BYTES_LEN + mac_len;

        if buf.len() < overall_len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        let mut v: Self = Self{
            base: base,
            hello_phase_vrf_mac: [0; MAX_HASH_MESSAGE_DIGEST_LEN]
        };

        v.hello_phase_vrf_mac[..mac_len]
            .copy_from_slice(&buf[FragmentHeader::BYTES_LEN..overall_len]);

        return Ok(v);

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<(), TsppError> {

        let mac_len: usize = self.base.length as usize;
        let overall_len: usize = FragmentHeader::BYTES_LEN + mac_len;

        if buf.len() < overall_len {
            return Err(TsppError::new(TsppErrorCode::BufferTooShort));
        }

        self.base.to_bytes(&mut buf[..]).unwrap();
        buf[FragmentHeader::BYTES_LEN..overall_len]
            .copy_from_slice(&self.hello_phase_vrf_mac[..mac_len]);

        return Ok(());

    }

}

struct UserStreamFragment {
    base: FragmentHeader,
    payload: Vec<u8>,
    tag: [u8; MAX_AEAD_TAG_LEN]
}

struct KeyUpdate {
    base: FragmentHeader
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

    /*

    やっぱこれ、utilのAeadとかを使うんじゃなくて、tspp::crypto::TsppAeadとかを作って
    それをCipherSuiteからアクセスできるようにmanagedにしたほうがいい（たとえば、Aes192Gcmとかってあんま使わんやろうから）。

    んで、let algo = TsppAeadAlgorhitm::Aes128Gcm;
    let aead = algo.new_instance()とかにしたり、

    let cs = CipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256;
    cs.new_aead() {
        algo.new_instance()
    }

    とかしたほうがいい

    */

    fn algorithms(&self) ->
        Result<(DiffieHellmanAlgorithm, DigitalSignatureAlgorithm, AeadAlgorithm, HashAlgorithm), TsppError> {
        return match self {
            Self::NULL_NULL_NULL_NULL                 => Err(TsppError::new(TsppErrorCode::IllegalCipherSuite)),
            Self::X25519_Ed25519_AES_128_GCM_SHA3_256 => Ok((
                DiffieHellmanAlgorithm::X25519,
                DigitalSignatureAlgorithm::Ed25519,
                AeadAlgorithm::Aes128Gcm,
                HashAlgorithm::Sha3256
            )),
        };
    }

    fn ke_algorithm(&self) -> Result<DiffieHellmanAlgorithm, TsppError> {
        return Ok(self.algorithms()?.0);
    }

    fn sign_algorithm(&self) -> Result<DigitalSignatureAlgorithm, TsppError> {
        return Ok(self.algorithms()?.1);
    }

    fn signer(&self, privkey: &[u8]) -> Result<DigitalSignatureSigner, TsppError> {
        return Ok(self.sign_algorithm()?.signer_instance(privkey)?);
    }

    fn verifier(&self, pubkey: &[u8]) -> Result<DigitalSignatureVerifier, TsppError> {
        return Ok(self.sign_algorithm()?.verifier_instance(pubkey)?);
    }

    fn aead_algorithm(&self) -> Result<AeadAlgorithm, TsppError> {
        return Ok(self.algorithms()?.2);
    }

    fn aead(&self, key: &[u8]) -> Result<Aead, TsppError> {
        return Ok(self.aead_algorithm()?.instance(key)?);
    }

    fn hash_algorithm(&self) -> Result<HashAlgorithm, TsppError> {
        return Ok(self.algorithms()?.3);
    }

    fn hash(&self) -> Result<Hash, TsppError> {
        return Ok(self.hash_algorithm()?.instance());
    }

}

// markers
