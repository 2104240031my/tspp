use cryptopkg::crypto::aes_aead::Aes128Ccm;
use cryptopkg::crypto::aes_aead::Aes192Ccm;
use cryptopkg::crypto::aes_aead::Aes256Ccm;
use cryptopkg::crypto::aes_aead::Aes128Gcm;
use cryptopkg::crypto::aes_aead::Aes192Gcm;
use cryptopkg::crypto::aes_aead::Aes256Gcm;
use cryptopkg::crypto::chacha20_poly1305::ChaCha20Poly1305;
use cryptopkg::crypto::ed25519::Ed25519Signer;
use cryptopkg::crypto::ed25519::Ed25519Verifier;
use cryptopkg::crypto::error::CryptoError;
use cryptopkg::crypto::feature::Aead as AeadFeature;
use cryptopkg::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use cryptopkg::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use cryptopkg::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use cryptopkg::crypto::feature::Hash as HashFeature;
use cryptopkg::crypto::feature::Mac as MacFeature;
use cryptopkg::crypto::hmac_sha2::HmacSha224;
use cryptopkg::crypto::hmac_sha2::HmacSha256;
use cryptopkg::crypto::hmac_sha2::HmacSha384;
use cryptopkg::crypto::hmac_sha2::HmacSha512;
use cryptopkg::crypto::hmac_sha3::HmacSha3224;
use cryptopkg::crypto::hmac_sha3::HmacSha3256;
use cryptopkg::crypto::hmac_sha3::HmacSha3384;
use cryptopkg::crypto::hmac_sha3::HmacSha3512;
use cryptopkg::crypto::sha2::Sha224;
use cryptopkg::crypto::sha2::Sha256;
use cryptopkg::crypto::sha2::Sha384;
use cryptopkg::crypto::sha2::Sha512;
use cryptopkg::crypto::sha3::Sha3224;
use cryptopkg::crypto::sha3::Sha3256;
use cryptopkg::crypto::sha3::Sha3384;
use cryptopkg::crypto::sha3::Sha3512;
use cryptopkg::crypto::x25519::X25519;

#[derive(Clone, Copy)]
pub enum AeadAlgorithm {
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub enum Aead {
    Aes128Ccm(Aes128Ccm),
    Aes192Ccm(Aes192Ccm),
    Aes256Ccm(Aes256Ccm),
    Aes128Gcm(Aes128Gcm),
    Aes192Gcm(Aes192Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadAlgorithm {

    pub fn instance(&self, key: &[u8]) -> Result<Aead, CryptoError> {
        return Aead::new(*self, key);
    }

    pub fn key_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::KEY_LEN,
            Self::Aes192Ccm        => Aes192Ccm::KEY_LEN,
            Self::Aes256Ccm        => Aes256Ccm::KEY_LEN,
            Self::Aes128Gcm        => Aes128Gcm::KEY_LEN,
            Self::Aes192Gcm        => Aes192Gcm::KEY_LEN,
            Self::Aes256Gcm        => Aes256Gcm::KEY_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::KEY_LEN,
        };
    }

    pub fn nonce_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::MAX_NONCE_LEN,
            Self::Aes192Ccm        => Aes192Ccm::MAX_NONCE_LEN,
            Self::Aes256Ccm        => Aes256Ccm::MAX_NONCE_LEN,
            Self::Aes128Gcm        => Aes128Gcm::MAX_NONCE_LEN,
            Self::Aes192Gcm        => Aes192Gcm::MAX_NONCE_LEN,
            Self::Aes256Gcm        => Aes256Gcm::MAX_NONCE_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::MAX_NONCE_LEN,
        };
    }

    pub fn tag_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::TAG_LEN,
            Self::Aes192Ccm        => Aes192Ccm::TAG_LEN,
            Self::Aes256Ccm        => Aes256Ccm::TAG_LEN,
            Self::Aes128Gcm        => Aes128Gcm::TAG_LEN,
            Self::Aes192Gcm        => Aes192Gcm::TAG_LEN,
            Self::Aes256Gcm        => Aes256Gcm::TAG_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::TAG_LEN,
        };
    }

}

impl Aead {

    pub fn new(algo: AeadAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            AeadAlgorithm::Aes128Ccm        => Ok(Self::Aes128Ccm(Aes128Ccm::new(key)?)),
            AeadAlgorithm::Aes192Ccm        => Ok(Self::Aes192Ccm(Aes192Ccm::new(key)?)),
            AeadAlgorithm::Aes256Ccm        => Ok(Self::Aes256Ccm(Aes256Ccm::new(key)?)),
            AeadAlgorithm::Aes128Gcm        => Ok(Self::Aes128Gcm(Aes128Gcm::new(key)?)),
            AeadAlgorithm::Aes192Gcm        => Ok(Self::Aes192Gcm(Aes192Gcm::new(key)?)),
            AeadAlgorithm::Aes256Gcm        => Ok(Self::Aes256Gcm(Aes256Gcm::new(key)?)),
            AeadAlgorithm::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Aes128Ccm(v)        => v.rekey(key).err(),
            Self::Aes192Ccm(v)        => v.rekey(key).err(),
            Self::Aes256Ccm(v)        => v.rekey(key).err(),
            Self::Aes128Gcm(v)        => v.rekey(key).err(),
            Self::Aes192Gcm(v)        => v.rekey(key).err(),
            Self::Aes256Gcm(v)        => v.rekey(key).err(),
            Self::ChaCha20Poly1305(v) => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

    pub fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
        };
    }

    pub fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes192Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes256Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes192Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
        };
    }

    pub fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes192Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes256Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes192Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
        };
    }

}

#[derive(Clone, Copy)]
pub enum DiffieHellmanAlgorithm {
    X25519,
}

pub enum DiffieHellman {
    X25519(X25519),
}

impl DiffieHellmanAlgorithm {

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PUBLIC_KEY_LEN,
        };
    }

    pub fn shared_secret_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::SHARED_SECRET_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn compute_shared_secret_oneshot(&self, priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_shared_secret_oneshot(priv_key,
                peer_pub_key, shared_secret),
        };
    }

}

#[derive(Clone, Copy)]
pub enum DigitalSignatureAlgorithm {
    Ed25519,
}

pub enum DigitalSignatureSigner {
    Ed25519(Ed25519Signer),
}

pub enum DigitalSignatureVerifier {
    Ed25519(Ed25519Verifier),
}

impl DigitalSignatureAlgorithm {

    pub fn signer_instance(&self, priv_key: &[u8]) -> Result<DigitalSignatureSigner, CryptoError> {
        return DigitalSignatureSigner::new(*self, priv_key);
    }

    pub fn verifier_instance(&self, pub_key: &[u8]) -> Result<DigitalSignatureVerifier, CryptoError> {
        return DigitalSignatureVerifier::new(*self, pub_key);
    }

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PUBLIC_KEY_LEN,
        };
    }

    pub fn signature_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::SIGNATURE_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn sign_oneshot(&self, priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::sign_oneshot(priv_key, msg, signature),
        };
    }

    pub fn verify_oneshot(&self, pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Verifier::verify_oneshot(pub_key, msg, signature),
        };
    }

}

impl DigitalSignatureSigner {

    pub fn new(algo: DigitalSignatureAlgorithm, priv_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Signer::new(priv_key)?)),
        };
    }

    pub fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(priv_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.compute_public_key(pub_key),
        };
    }

    pub fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.sign(msg, signature),
        };
    }

}

impl DigitalSignatureVerifier {

    pub fn new(algo: DigitalSignatureAlgorithm, pub_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Verifier::new(pub_key)?)),
        };
    }

    pub fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(pub_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519(v) => v.verify(msg, signature),
        };
    }

}

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3224,
    Sha3256,
    Sha3384,
    Sha3512,
}

pub enum Hash {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha3224(Sha3224),
    Sha3256(Sha3256),
    Sha3384(Sha3384),
    Sha3512(Sha3512),
}

impl HashAlgorithm {

    pub fn instance(&self) -> Hash {
        return Hash::new(*self);
    }

    pub fn md_len(&self) -> usize {
        return match self {
            Self::Sha224    => Sha224::MESSAGE_DIGEST_LEN,
            Self::Sha256    => Sha256::MESSAGE_DIGEST_LEN,
            Self::Sha384    => Sha384::MESSAGE_DIGEST_LEN,
            Self::Sha512    => Sha512::MESSAGE_DIGEST_LEN,
            Self::Sha3224   => Sha3224::MESSAGE_DIGEST_LEN,
            Self::Sha3256   => Sha3256::MESSAGE_DIGEST_LEN,
            Self::Sha3384   => Sha3384::MESSAGE_DIGEST_LEN,
            Self::Sha3512   => Sha3512::MESSAGE_DIGEST_LEN,
        };
    }

    pub fn digest_oneshot(&self, msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Sha224    => Sha224::digest_oneshot(msg, md),
            Self::Sha256    => Sha256::digest_oneshot(msg, md),
            Self::Sha384    => Sha384::digest_oneshot(msg, md),
            Self::Sha512    => Sha512::digest_oneshot(msg, md),
            Self::Sha3224   => Sha3224::digest_oneshot(msg, md),
            Self::Sha3256   => Sha3256::digest_oneshot(msg, md),
            Self::Sha3384   => Sha3384::digest_oneshot(msg, md),
            Self::Sha3512   => Sha3512::digest_oneshot(msg, md),
        };
    }

}

impl Hash {

    pub fn new(algo: HashAlgorithm) -> Self {
        return match algo {
            HashAlgorithm::Sha224    => Self::Sha224(Sha224::new()),
            HashAlgorithm::Sha256    => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384    => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512    => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha3224   => Self::Sha3224(Sha3224::new()),
            HashAlgorithm::Sha3256   => Self::Sha3256(Sha3256::new()),
            HashAlgorithm::Sha3384   => Self::Sha3384(Sha3384::new()),
            HashAlgorithm::Sha3512   => Self::Sha3512(Sha3512::new()),
        };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.reset().err(),
            Self::Sha256(v)    => v.reset().err(),
            Self::Sha384(v)    => v.reset().err(),
            Self::Sha512(v)    => v.reset().err(),
            Self::Sha3224(v)   => v.reset().err(),
            Self::Sha3256(v)   => v.reset().err(),
            Self::Sha3384(v)   => v.reset().err(),
            Self::Sha3512(v)   => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.update(msg).err(),
            Self::Sha256(v)    => v.update(msg).err(),
            Self::Sha384(v)    => v.update(msg).err(),
            Self::Sha512(v)    => v.update(msg).err(),
            Self::Sha3224(v)   => v.update(msg).err(),
            Self::Sha3256(v)   => v.update(msg).err(),
            Self::Sha3384(v)   => v.update(msg).err(),
            Self::Sha3512(v)   => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.digest(md).err(),
            Self::Sha256(v)    => v.digest(md).err(),
            Self::Sha384(v)    => v.digest(md).err(),
            Self::Sha512(v)    => v.digest(md).err(),
            Self::Sha3224(v)   => v.digest(md).err(),
            Self::Sha3256(v)   => v.digest(md).err(),
            Self::Sha3384(v)   => v.digest(md).err(),
            Self::Sha3512(v)   => v.digest(md).err(),
        } { Err(e) } else { Ok(()) };
    }

}

#[derive(Clone, Copy)]
pub enum MacAlgorithm {
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha3224,
    HmacSha3256,
    HmacSha3384,
    HmacSha3512,
}

pub enum Mac {
    HmacSha224(HmacSha224),
    HmacSha256(HmacSha256),
    HmacSha384(HmacSha384),
    HmacSha512(HmacSha512),
    HmacSha3224(HmacSha3224),
    HmacSha3256(HmacSha3256),
    HmacSha3384(HmacSha3384),
    HmacSha3512(HmacSha3512),
}

impl MacAlgorithm {

    pub fn instance(&self, key: &[u8]) -> Result<Mac, CryptoError> {
        return Mac::new(*self, key);
    }

    pub fn mac_len(&self) -> usize {
        return match self {
            Self::HmacSha224  => HmacSha224::MAC_LEN,
            Self::HmacSha256  => HmacSha256::MAC_LEN,
            Self::HmacSha384  => HmacSha384::MAC_LEN,
            Self::HmacSha512  => HmacSha512::MAC_LEN,
            Self::HmacSha3224 => HmacSha3224::MAC_LEN,
            Self::HmacSha3256 => HmacSha3256::MAC_LEN,
            Self::HmacSha3384 => HmacSha3384::MAC_LEN,
            Self::HmacSha3512 => HmacSha3512::MAC_LEN,
        };
    }

    pub fn compute_oneshot(&self, key: &[u8], msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha224  => HmacSha224::compute_oneshot(key, msg, md),
            Self::HmacSha256  => HmacSha256::compute_oneshot(key, msg, md),
            Self::HmacSha384  => HmacSha384::compute_oneshot(key, msg, md),
            Self::HmacSha512  => HmacSha512::compute_oneshot(key, msg, md),
            Self::HmacSha3224 => HmacSha3224::compute_oneshot(key, msg, md),
            Self::HmacSha3256 => HmacSha3256::compute_oneshot(key, msg, md),
            Self::HmacSha3384 => HmacSha3384::compute_oneshot(key, msg, md),
            Self::HmacSha3512 => HmacSha3512::compute_oneshot(key, msg, md),
        };
    }

}

impl Mac {

    pub fn new(algo: MacAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            MacAlgorithm::HmacSha224  => Ok(Self::HmacSha224(HmacSha224::new(key)?)),
            MacAlgorithm::HmacSha256  => Ok(Self::HmacSha256(HmacSha256::new(key)?)),
            MacAlgorithm::HmacSha384  => Ok(Self::HmacSha384(HmacSha384::new(key)?)),
            MacAlgorithm::HmacSha512  => Ok(Self::HmacSha512(HmacSha512::new(key)?)),
            MacAlgorithm::HmacSha3224 => Ok(Self::HmacSha3224(HmacSha3224::new(key)?)),
            MacAlgorithm::HmacSha3256 => Ok(Self::HmacSha3256(HmacSha3256::new(key)?)),
            MacAlgorithm::HmacSha3384 => Ok(Self::HmacSha3384(HmacSha3384::new(key)?)),
            MacAlgorithm::HmacSha3512 => Ok(Self::HmacSha3512(HmacSha3512::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.rekey(key).err(),
            Self::HmacSha256(v)  => v.rekey(key).err(),
            Self::HmacSha384(v)  => v.rekey(key).err(),
            Self::HmacSha512(v)  => v.rekey(key).err(),
            Self::HmacSha3224(v) => v.rekey(key).err(),
            Self::HmacSha3256(v) => v.rekey(key).err(),
            Self::HmacSha3384(v) => v.rekey(key).err(),
            Self::HmacSha3512(v) => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.reset().err(),
            Self::HmacSha256(v)  => v.reset().err(),
            Self::HmacSha384(v)  => v.reset().err(),
            Self::HmacSha512(v)  => v.reset().err(),
            Self::HmacSha3224(v) => v.reset().err(),
            Self::HmacSha3256(v) => v.reset().err(),
            Self::HmacSha3384(v) => v.reset().err(),
            Self::HmacSha3512(v) => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.update(msg).err(),
            Self::HmacSha256(v)  => v.update(msg).err(),
            Self::HmacSha384(v)  => v.update(msg).err(),
            Self::HmacSha512(v)  => v.update(msg).err(),
            Self::HmacSha3224(v) => v.update(msg).err(),
            Self::HmacSha3256(v) => v.update(msg).err(),
            Self::HmacSha3384(v) => v.update(msg).err(),
            Self::HmacSha3512(v) => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha224(v)  => v.compute(mac),
            Self::HmacSha256(v)  => v.compute(mac),
            Self::HmacSha384(v)  => v.compute(mac),
            Self::HmacSha512(v)  => v.compute(mac),
            Self::HmacSha3224(v) => v.compute(mac),
            Self::HmacSha3256(v) => v.compute(mac),
            Self::HmacSha3384(v) => v.compute(mac),
            Self::HmacSha3512(v) => v.compute(mac),
        };
    }

}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {

    if a.len() != b.len() {
        return false;
    }

    let mut s: u8 = 0;

    for i in 0..a.len() {
        s = s | (a[i] ^ b[i]);
    }

    return s == 0;

}