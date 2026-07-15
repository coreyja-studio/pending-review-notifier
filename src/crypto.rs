//! XChaCha20-Poly1305 encryption for GitHub tokens at rest.
//!
//! Wire format: 24-byte random nonce || ciphertext (which includes the
//! 16-byte Poly1305 tag). XChaCha20's 192-bit nonce makes a random nonce
//! per encryption safe — we re-encrypt on every token refresh (see
//! docs/DESIGN.md "Token encryption"). No key rotation in v1.

use base64::Engine as _;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use cja::color_eyre::eyre::{WrapErr as _, eyre};

const NONCE_LEN: usize = 24;

/// Encrypts and decrypts GitHub tokens for storage. Cheap to clone.
///
/// Deliberately does not implement `Debug` — it holds key material.
#[derive(Clone)]
pub struct TokenCrypto {
    cipher: XChaCha20Poly1305,
}

impl TokenCrypto {
    /// Build from a base64-encoded 32-byte key (the `TOKEN_ENC_KEY` env var).
    ///
    /// Fails if the value is not valid base64 or does not decode to exactly
    /// 32 bytes — call this at startup so a misconfigured key fails fast.
    pub fn from_base64_key(key_b64: &str) -> cja::Result<Self> {
        let key = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .wrap_err("TOKEN_ENC_KEY is not valid base64")?;
        let key: [u8; 32] = key.try_into().map_err(|bad: Vec<u8>| {
            eyre!(
                "TOKEN_ENC_KEY must decode to exactly 32 bytes, got {}",
                bad.len()
            )
        })?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key.into()),
        })
    }

    /// Encrypt a token. Returns `nonce || ciphertext+tag`.
    pub fn encrypt(&self, plaintext: &str) -> cja::Result<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            // aead's error type is deliberately opaque; ours carries no
            // secrets either.
            .map_err(|_| eyre!("token encryption failed"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt `nonce || ciphertext+tag`, validating the tag.
    pub fn decrypt(&self, data: &[u8]) -> cja::Result<String> {
        let (nonce, ciphertext) = data
            .split_at_checked(NONCE_LEN)
            .ok_or_else(|| eyre!("encrypted token is too short to contain a nonce"))?;
        let plaintext = self
            .cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| eyre!("token decryption failed (tampered data or wrong key)"))?;
        String::from_utf8(plaintext).wrap_err("decrypted token is not valid UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_b64(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn crypto(byte: u8) -> TokenCrypto {
        TokenCrypto::from_base64_key(&key_b64(byte)).unwrap()
    }

    #[test]
    fn roundtrip() {
        let c = crypto(0x42);
        let enc = c.encrypt("gho_secret_token_value").unwrap();
        assert_eq!(c.decrypt(&enc).unwrap(), "gho_secret_token_value");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let c = crypto(0x42);
        let mut enc = c.encrypt("gho_secret_token_value").unwrap();
        // Flip a bit in the ciphertext body (past the nonce).
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        assert!(c.decrypt(&enc).is_err());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let c = crypto(0x42);
        let mut enc = c.encrypt("gho_secret_token_value").unwrap();
        enc[0] ^= 0x01;
        assert!(c.decrypt(&enc).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let enc = crypto(0x42).encrypt("gho_secret_token_value").unwrap();
        assert!(crypto(0x43).decrypt(&enc).is_err());
    }

    #[test]
    fn nonce_is_unique_across_calls() {
        let c = crypto(0x42);
        let a = c.encrypt("same plaintext").unwrap();
        let b = c.encrypt("same plaintext").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonces must not repeat");
        assert_ne!(a, b);
    }

    #[test]
    fn key_must_be_32_bytes() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(TokenCrypto::from_base64_key(&short).is_err());
        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 33]);
        assert!(TokenCrypto::from_base64_key(&long).is_err());
        assert!(TokenCrypto::from_base64_key("not base64!!!").is_err());
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let c = crypto(0x42);
        assert!(c.decrypt(&[0u8; 10]).is_err());
    }
}
