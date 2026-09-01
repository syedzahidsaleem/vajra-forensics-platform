//! Digital signatures and X.509 PKI primitives (§40).

use crate::error::AuditError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

/// Operator cryptographic keypair for digital signatures and PKI attestation (§40).
pub struct OperatorKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl OperatorKeyPair {
    /// Generates a new cryptographic keypair using cryptographically secure OS RNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Loads a keypair from raw 32-byte secret key material.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Signs an arbitrary byte slice using Ed25519 (§40).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(data);
        sig.to_bytes().to_vec()
    }

    /// Returns the 32-byte public verifying key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Generates a self-signed X.509 certificate for this operator (§40).
    pub fn generate_self_signed_cert(&self, operator_id: &str) -> Result<String, AuditError> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("Vajra Operator: {}", operator_id));
        dn.push(DnType::OrganizationName, "Vajra Digital Forensics Platform");
        dn.push(DnType::CountryName, "IN");

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;

        // Construct PKCS#8 PEM for Ed25519 from secret key seed
        let secret_bytes = self.signing_key.to_bytes();
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ];
        pkcs8.extend_from_slice(&secret_bytes);

        let b64 = base64_encode(&pkcs8);
        let pem_str = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64);

        let rcgen_key = KeyPair::from_pem(&pem_str)
            .map_err(|e| AuditError::PkiError(format!("Key derivation failed: {}", e)))?;
        let cert = params
            .self_signed(&rcgen_key)
            .map_err(|e| AuditError::PkiError(format!("Certificate generation failed: {}", e)))?;

        Ok(cert.pem())
    }
}

/// Standard base64 encoding helper for PKI serialization.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Verifies an Ed25519 digital signature against public key bytes (§40).
pub fn verify_signature(
    public_key_bytes: &[u8],
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, AuditError> {
    if public_key_bytes.len() != 32 {
        return Err(AuditError::InvalidSignature(format!(
            "Invalid public key length: expected 32 bytes, got {}",
            public_key_bytes.len()
        )));
    }

    if signature_bytes.len() != 64 {
        return Err(AuditError::InvalidSignature(format!(
            "Invalid signature length: expected 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(public_key_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| AuditError::InvalidSignature(format!("Invalid public key: {}", e)))?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
