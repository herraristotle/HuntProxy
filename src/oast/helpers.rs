//! Crypto and id helpers for the OAST providers.
//!
//! Protocol facts verified against the local interactsh clone
//! (`pkg/client/client.go`, `pkg/server/util.go`) — see `docs/specs/SPEC-oast.md`.

use crate::domain::{DomainError, DomainResult, ErrorCode};
use aes::Aes256;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2_11::Sha256;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

const XID_ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
pub const CORRELATION_ID_LEN: usize = 20;
pub const NONCE_LEN: usize = 13;
const RSA_BITS: usize = 2048;

/// MSB-first base32 (RFC 4648 grouping, no padding) with a custom alphabet.
fn base32_encode(data: &[u8], alphabet: &[u8; 32]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(alphabet[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(alphabet[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// Privacy-preserving xid: 4-byte BE unix timestamp + 8 crypto-random bytes,
/// encoded to exactly 20 chars of `[0-9a-v]` (matches Go
/// `newAnonymousCorrelationID` + `CorrelationIdLengthDefault`).
pub(crate) fn anonymous_correlation_id() -> String {
    let mut raw = [0u8; 12];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    raw[..4].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut raw[4..]);
    let encoded = base32_encode(&raw, XID_ALPHABET);
    encoded
        .char_indices()
        .take(CORRELATION_ID_LEN)
        .map(|(_, c)| c)
        .collect()
}

/// Fresh nonce label suffix: 13 random bytes → z-base-32, truncated to 13
/// chars (matches Go `Client.URL()` using `CorrelationIdNonceLengthDefault`).
pub(crate) fn mint_nonce() -> String {
    let mut raw = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);
    base32_encode(&raw, ZBASE32_ALPHABET)
        .chars()
        .take(NONCE_LEN)
        .collect()
}

/// Full payload label = `{cid}{nonce}` (33 chars; xid alphabet then
/// z-base-32 alphabet — exactly what `isCorrelationID` validates).
pub(crate) fn mint_label(correlation_id: &str) -> String {
    format!("{correlation_id}{}", mint_nonce())
}

/// RSA-2048 keypair. Returns `(pkcs8_private_pem, public_key_b64)` where the
/// b64 payload is `base64(PEM(PKIX SPKI))` — the exact `public-key` field the
/// interactsh server feeds to `pem.Decode` + `x509.ParsePKIXPublicKey`.
pub(crate) fn generate_rsa_keypair() -> DomainResult<(String, String)> {
    let private = RsaPrivateKey::new(&mut rand0::rng(), RSA_BITS)
        .map_err(|e| internal_error(format!("rsa keygen: {e}")))?;
    let private_pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| internal_error(format!("rsa pem encode: {e}")))?
        .to_string();
    let spki = RsaPublicKey::from(&private)
        .to_public_key_der()
        .map_err(|e| internal_error(format!("rsa spki encode: {e}")))?;
    let b64_lines = wrap_pem_body(&B64.encode(spki.as_ref()));
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64_lines}\n-----END PUBLIC KEY-----\n");
    Ok((private_pem, B64.encode(pem)))
}

fn wrap_pem_body(b64: &str) -> String {
    b64.as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// RSA-OAEP-SHA256 unwrap of the poll response `aes_key` (Go
/// `rsa.DecryptOAEP(sha256.New(), ...)`). Returns the raw 32-byte AES key.
pub(crate) fn unwrap_aes_key(private_pem: &str, aes_key_b64: &str) -> DomainResult<Vec<u8>> {
    let private = RsaPrivateKey::from_pkcs8_pem(private_pem)
        .map_err(|e| protocol_error(format!("rsa private key parse: {e}")))?;
    let wrapped = B64
        .decode(aes_key_b64.trim())
        .map_err(|e| protocol_error(format!("aes_key base64: {e}")))?;
    let key = private
        .decrypt(Oaep::<Sha256>::new(), &wrapped)
        .map_err(|e| protocol_error(format!("aes_key rsa unwrap: {e}")))?;
    if key.len() != 32 {
        return Err(protocol_error(format!(
            "aes_key length {} (expected 32)",
            key.len()
        )));
    }
    Ok(key)
}

/// AES-256-CTR decrypt: blob = `IV(16 bytes) || ciphertext` (Go
/// `cipher.NewCTR` = big-endian 128-bit counter → `Ctr128BE`).
pub(crate) fn aes_ctr_decrypt(key: &[u8], blob: &[u8]) -> DomainResult<Vec<u8>> {
    if blob.len() < 16 {
        return Err(protocol_error("interaction blob shorter than IV"));
    }
    let mut data = blob[16..].to_vec();
    let mut cipher = Aes256Ctr::new_from_slices(key, &blob[..16])
        .map_err(|e| protocol_error(format!("aes-ctr init: {e}")))?;
    cipher.apply_keystream(&mut data);
    Ok(data)
}

fn internal_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::Internal, message.into())
}

fn protocol_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::ProtocolError, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::GenericArray;
    use rsa::pkcs8::DecodePublicKey;

    #[test]
    fn correlation_id_is_20_chars_of_xid_alphabet() {
        let id = anonymous_correlation_id();
        assert_eq!(id.len(), CORRELATION_ID_LEN);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='v').contains(&c)));
        // Distinct on consecutive calls.
        assert_ne!(anonymous_correlation_id(), id);
    }

    #[test]
    fn base32_xid_golden_vector_matches_manual_bit_grouping() {
        // 12 bytes: 4-byte BE time 0x00000001 + 8 zero bytes. The single set
        // bit sits at stream position 31 → group 6 = 0b01000 = 8.
        let raw = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let expected = format!("0000008{}", "0".repeat(13));
        assert_eq!(base32_encode(&raw, XID_ALPHABET), expected);
    }

    #[test]
    fn zbase32_golden_vector() {
        // 0xff = 11111111 → g0 = 11111 (31 → '9'), g1 = 11 + 00 pad = 28 → 'h'.
        assert_eq!(base32_encode(&[0xff], ZBASE32_ALPHABET), "9h");
    }

    #[test]
    fn nonce_and_label_shapes_match_server_validator() {
        let nonce = mint_nonce();
        assert_eq!(nonce.len(), NONCE_LEN);
        assert!(nonce.chars().all(|c| ZBASE32_ALPHABET.contains(&(c as u8))));
        let cid = anonymous_correlation_id();
        let label = mint_label(&cid);
        assert_eq!(label.len(), CORRELATION_ID_LEN + NONCE_LEN);
        assert!(label
            .chars()
            .take(CORRELATION_ID_LEN)
            .all(|c| XID_ALPHABET.contains(&(c as u8))));
        assert!(label
            .chars()
            .skip(CORRELATION_ID_LEN)
            .all(|c| ZBASE32_ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn rsa_keygen_public_key_payload_round_trips_through_pem() {
        let (private_pem, public_b64) = generate_rsa_keypair().unwrap();
        let pem_text = String::from_utf8(B64.decode(&public_b64).unwrap()).unwrap();
        assert!(pem_text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem_text.trim_end().ends_with("-----END PUBLIC KEY-----"));
        // Parse the PEM back to SPKI and confirm it pairs with the private key.
        let b64_body: String = pem_text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>();
        let der = B64.decode(b64_body).unwrap();
        let public = RsaPublicKey::from_public_key_der(&der).unwrap();
        let private = RsaPrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(
            RsaPublicKey::from(&private).to_public_key_der().unwrap(),
            public.to_public_key_der().unwrap()
        );
    }

    #[test]
    fn oaep_and_ctr_decrypt_round_trip() {
        let private = RsaPrivateKey::new(&mut rand0::rng(), RSA_BITS).unwrap();
        let public = RsaPublicKey::from(&private);

        // Wrap a random AES key exactly like the server does.
        let mut aes_key = [7u8; 32];
        rand::thread_rng().fill_bytes(&mut aes_key);
        let wrapped = public
            .encrypt(&mut rand0::rng(), Oaep::<Sha256>::new(), &aes_key)
            .unwrap();
        let unwrapped = unwrap_aes_key(
            private
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .as_ref(),
            &B64.encode(wrapped),
        )
        .unwrap();
        assert_eq!(unwrapped, aes_key);

        // Build an IV + CTR ciphertext blob and decrypt it.
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let plaintext = b"{\"protocol\":\"http\",\"full-id\":\"abc\"}";
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&aes_key),
            GenericArray::from_slice(&iv),
        );
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let mut blob = iv.to_vec();
        blob.extend_from_slice(&ciphertext);
        let decrypted = aes_ctr_decrypt(&aes_key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn short_blob_is_rejected() {
        assert!(aes_ctr_decrypt(&[0u8; 32], &[0u8; 8]).is_err());
    }
}
