use aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use uuid::Uuid;
use rand::Rng;
use anyhow::{Result, Error};


pub const CONTROL_PORT: u16 = 7835;
pub const SAFE_MAX_SIZE: usize = 512;

#[derive(Copy, Clone)]
pub enum EncryptMethod {
    UNSAFE = 0,
    AES = 1,
    CHACHA = 2,
}

pub struct Authenticator {
    client_id: Uuid,
    /// Aes-128-gcm needs 16 bytes to generate a key
    /// Chacha20-poly1305 needs 32 bytes to generate a key
    /// length other than 16/32 will cause failure
    key: [u8; 32],
    // nonce here is only bytes, turn it into corresponding
    // Nonce before using
    nonce: [u8; 12],
    method: EncryptMethod,
}

impl EncryptMethod {
    pub fn from_num(num: u8) -> EncryptMethod {
        match num {
            1 => EncryptMethod::AES,
            2 => EncryptMethod::CHACHA,
            0 | _ => EncryptMethod::UNSAFE,
        }
    }

    pub fn to_num(&self) -> u8 {
        match self {
            EncryptMethod::UNSAFE => 0,
            EncryptMethod::AES => 1,
            EncryptMethod::CHACHA => 2,
        }
    }
}

impl Authenticator {
    pub fn new(id: Uuid, key: [u8; 32], method: EncryptMethod) -> Result<Authenticator> {
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 12] = rng.gen();
        match method {
            EncryptMethod::AES => {
                Ok(Authenticator{
                    client_id: id,
                    key,
                    nonce: nonce_bytes,
                    method: EncryptMethod::AES,
                })
            },
            EncryptMethod::CHACHA => {
                if key.len() == 32 {
                    Ok(Authenticator{
                        client_id: id,
                        key,
                        nonce: nonce_bytes,
                        method: EncryptMethod::CHACHA,
                    })
                } else { Err(Error::msg("Key should be exactly 32 bytes long for chacha20-poly1305")) }
            },
            EncryptMethod::UNSAFE  => {
                Err(Error::msg("Could not generate Authenticator with Unsafe mode"))
            }
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match self.method {
            EncryptMethod::AES => {
                let seed = &self.key[0..16];
                let key = AesKey::<Aes128Gcm>::from_slice(seed);
                let cipher = Aes128Gcm::new(key);
                let nonce = AesNonce::from_slice(&self.nonce);
                let ciphertext = cipher.encrypt(nonce, plaintext)?;
                Ok(ciphertext)
            },
            EncryptMethod::CHACHA => {
                let key = ChaChaKey::from_slice(&self.key);
                let nonce = ChaChaNonce::from_slice(&self.nonce);
                let cipher = ChaCha20Poly1305::new(&key);
                let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
                Ok(ciphertext)
            }
            _ => { Err(aead::Error)}
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match self.method {
            EncryptMethod::AES => {
                let seed = &self.key[0..16];
                let key = AesKey::<Aes128Gcm>::from_slice(seed);
                let cipher = Aes128Gcm::new(key);
                let nonce = AesNonce::from_slice(&self.nonce);
                let plaintext = cipher.decrypt(nonce, ciphertext)?;
                Ok(plaintext)
            },
            EncryptMethod::CHACHA => {
                let key = ChaChaKey::from_slice(&self.key);
                let nonce = ChaChaNonce::from_slice(&self.nonce);
                let cipher = ChaCha20Poly1305::new(&key);
                let plaintext = cipher.decrypt(nonce, ciphertext)?;
                Ok(plaintext)
            },
            _ => { Err(aead::Error) }
        }
    }

    pub fn get_nonce(&self) -> [u8; 12] {
        self.nonce
    }


}

