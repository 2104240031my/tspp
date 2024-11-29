use crypto::crypto::Aead;
use crypto::crypto::BlockCipher;
use crypto::crypto::CryptoError;
use crypto::crypto::CryptoErrorCode;
use crypto::crypto::Hash;
use crypto::crypto::Mac;
use crypto::crypto::aes::Aes256;
use crypto::crypto::block_cipher_mode::BlockCipherMode128;
use crypto::crypto::block_cipher_mode::Ctr128;
use crypto::crypto::block_cipher_mode::Gcm128;
use crypto::crypto::hmac_sha3::HmacSha3256;
use crypto::crypto::sha3::Sha3256;

pub struct Aes256Gcm {
    cipher: Aes256
}

pub struct Aes256CtrHmacSha3256 {
    cipher: Aes256,
    hmac: HmacSha3256
}

impl Aes256Gcm {

    pub const KEY_LEN: usize   = Aes256::KEY_LEN;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize   = Aes256::BLOCK_SIZE;

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ cipher: Aes256::new(key)? });
    }

}

impl Aead for Aes256Gcm {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.cipher.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate(&self.cipher, nonce, aad, plaintext, ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify(&self.cipher, nonce, aad, ciphertext, plaintext, tag);
    }

}

impl Aes256CtrHmacSha3256 {

    pub const KEY_LEN: usize   = Aes256::KEY_LEN;
    pub const NONCE_LEN: usize = 12;
    pub const MAC_LEN: usize   = HmacSha3256::MAC_LEN;

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {

        let cipher: Aes256 = Aes256::new(key)?;

        let mut h0: [u8; 16] = [0; 16];
        cipher.encrypt_overwrite_unchecked(&mut h0[..]);

        let mut h: [u8; 32] = [0; 32];
        Sha3256::digest_oneshot(&h0[..], &mut h[..])?;

        return Ok(Self{
            cipher: cipher,
            hmac: HmacSha3256::new(&h[..])?
        });

    }

}

impl Aead for Aes256CtrHmacSha3256 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() != Aes256::KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.cipher.rekey(key)?;

        let mut h0: [u8; 16] = [0; 16];
        self.cipher.encrypt_overwrite_unchecked(&mut h0[..]);

        let mut h: [u8; 32] = [0; 32];
        Sha3256::digest_oneshot(&h0[..], &mut h[..])?;

        self.hmac.rekey(&h[..])?;

        return Ok(self);

    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if nonce.len() != Self::NONCE_LEN || len != ciphertext.len() || tag.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr0: [u8; 16] = [0; 16];
        ctr0[..12].copy_from_slice(nonce);

        let mut ctr: [u8; 16] = [0; 16];
        let mut a: usize = 2;
        for i in (0..16).rev() {
            a = a + (ctr0[i] as usize);
            ctr[i] = a as u8;
            a = a >> 8;
        }

        BlockCipherMode128::ctr_encrypt_or_decrypt(&self.cipher, &mut ctr[..], 4, plaintext, ciphertext)?;

        let mut t: [u8; 32] = [0; 32];
        let pad: [u8; 16] = [0; 16];
        self.hmac
            .reset()?
            .update(aad)?
            .update(&pad[..((16 - (aad.len() & 15)) & 15)])?
            .update(ciphertext)?
            .update(&pad[..((16 - (len & 15)) & 15)])?
            .update(&(aad.len() as u64).to_le_bytes())?
            .update(&(len as u64).to_le_bytes())?
            .compute(&mut t[..])?;

        BlockCipherMode128::ctr_encrypt_or_decrypt(&self.cipher, &mut ctr0[..], 4, &t[..], tag)?;

        return Ok(());

    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {

        let len: usize = ciphertext.len();

        if nonce.len() != Self::NONCE_LEN || len != plaintext.len() || tag.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr: [u8; 16] = [0; 16];
        ctr[..12].copy_from_slice(nonce);

        let mut t: [u8; 32] = [0; 32];
        let mut u: [u8; 32] = [0; 32];
        let pad: [u8; 16] = [0; 16];
        self.hmac
            .reset()?
            .update(aad)?
            .update(&pad[..((16 - (aad.len() & 15)) & 15)])?
            .update(ciphertext)?
            .update(&pad[..((16 - (len & 15)) & 15)])?
            .update(&(aad.len() as u64).to_le_bytes())?
            .update(&(len as u64).to_le_bytes())?
            .compute(&mut u[..])?;

        BlockCipherMode128::ctr_encrypt_or_decrypt(&self.cipher, &mut ctr[..], 4, &u[..], &mut t[..])?;

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ t[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        BlockCipherMode128::ctr_encrypt_or_decrypt(&self.cipher, &mut ctr[..], 4, ciphertext, plaintext)?;

        return Ok(true);

    }

}