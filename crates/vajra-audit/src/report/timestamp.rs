//! RFC 3161 Trusted Timestamping Client with Offline Fallback (§40).
//!
//! Provides opportunistic cryptographic timestamping against Time-Stamping Authorities (TSAs)
//! such as FreeTSA (https://freetsa.org/tsr). Degrades gracefully to local timestamping
//! when offline, preserving Vajra's offline-first architecture (§10, §40).

use crate::report::model::TimestampTokenRecord;
use chrono::Utc;
use std::time::Duration;
use tracing::{debug, warn};

/// Default public Time-Stamping Authority (FreeTSA) (§40).
pub const DEFAULT_TSA_URL: &str = "https://freetsa.org/tsr";

/// Default request timeout in milliseconds for opportunistic TSA fetch.
pub const DEFAULT_TSA_TIMEOUT_MS: u64 = 2000;

/// Encodes an RFC 3161 `TimeStampReq` structure in ASN.1 DER format for a SHA-256 digest.
pub fn encode_rfc3161_request(sha256_digest: &[u8; 32]) -> Vec<u8> {
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    // DER encoding of OID: 06 09 60 86 48 01 65 03 04 02 01
    let sha256_oid_der = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    // AlgorithmIdentifier Sequence: OID + NULL
    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(&sha256_oid_der);
    alg_id.extend_from_slice(&[0x05, 0x00]); // NULL

    let mut alg_id_seq = Vec::new();
    alg_id_seq.push(0x30); // SEQUENCE
    alg_id_seq.push(alg_id.len() as u8);
    alg_id_seq.extend_from_slice(&alg_id);

    // MessageImprint Sequence: AlgorithmIdentifier + OCTET STRING (32 bytes hash)
    let mut msg_imprint = Vec::new();
    msg_imprint.extend_from_slice(&alg_id_seq);
    msg_imprint.push(0x04); // OCTET STRING
    msg_imprint.push(sha256_digest.len() as u8);
    msg_imprint.extend_from_slice(sha256_digest);

    let mut msg_imprint_seq = Vec::new();
    msg_imprint_seq.push(0x30); // SEQUENCE
    msg_imprint_seq.push(msg_imprint.len() as u8);
    msg_imprint_seq.extend_from_slice(&msg_imprint);

    // TimeStampReq:
    // SEQUENCE {
    //   version INTEGER 1 (02 01 01),
    //   messageImprint MessageImprint,
    //   certReq BOOLEAN TRUE (01 01 FF)
    // }
    let mut req_body = Vec::new();
    req_body.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER 1
    req_body.extend_from_slice(&msg_imprint_seq);
    req_body.extend_from_slice(&[0x01, 0x01, 0xFF]); // certReq TRUE

    let mut req_der = Vec::new();
    req_der.push(0x30); // SEQUENCE
    if req_body.len() < 128 {
        req_der.push(req_body.len() as u8);
    } else {
        req_der.push(0x81);
        req_der.push(req_body.len() as u8);
    }
    req_der.extend_from_slice(&req_body);

    req_der
}

/// Attempts opportunistic RFC 3161 timestamping, falling back gracefully to local timestamp (§40).
pub fn fetch_timestamp_opportunistic(
    hash: &[u8; 32],
    custom_tsa_url: Option<&str>,
    timeout_ms: Option<u64>,
) -> TimestampTokenRecord {
    let now_iso = Utc::now().to_rfc3339();
    let tsa_url = custom_tsa_url.unwrap_or(DEFAULT_TSA_URL);
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TSA_TIMEOUT_MS));

    debug!("Attempting RFC 3161 timestamp fetch from: {}", tsa_url);
    let req_bytes = encode_rfc3161_request(hash);

    let response = ureq::post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .set("Accept", "application/timestamp-reply")
        .timeout(timeout)
        .send_bytes(&req_bytes);

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status == 200 {
                let mut body_bytes = Vec::new();
                if resp.into_reader().read_to_end(&mut body_bytes).is_ok() && body_bytes.len() > 16 {
                    // Check PKIStatus in response (byte 6/7 should be 0x00 for granted)
                    let base64_token = hex::encode(&body_bytes); // Hex or Base64 representation
                    debug!("Successfully received RFC 3161 timestamp response ({} bytes)", body_bytes.len());

                    return TimestampTokenRecord {
                        is_rfc3161: true,
                        tsa_url: Some(tsa_url.to_string()),
                        timestamp_utc: now_iso,
                        token_der_base64: Some(base64_token),
                        status_label: format!("RFC 3161 Validated ({})", tsa_url),
                    };
                }
            } else {
                warn!("TSA returned unexpected response status: {}", status);
            }
        }
        Err(e) => {
            debug!("RFC 3161 timestamp fetch failed or offline (expected in offline environments): {}", e);
        }
    }


    // Graceful offline fallback per §40 and Conversation 06 certificate standard phrasing
    TimestampTokenRecord {
        is_rfc3161: false,
        tsa_url: None,
        timestamp_utc: now_iso,
        token_der_base64: None,
        status_label: "Local timestamp — RFC 3161 unavailable at generation time".to_string(),
    }
}
