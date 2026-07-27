use base64::prelude::{BASE64_STANDARD, Engine as _};
use rand::RngCore;
use sha1::{Digest, Sha1};

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-5AB5DC30CE87";

pub const TLS_RECORD_HEADER_SIZE: usize = 5;
pub const TLS_MAX_PLAINTEXT: usize = 16384;

// --- TLS handshake builders ---

pub fn wrap_tls_handshake(hs_type: u8, body: &[u8], record_version: [u8; 2]) -> Vec<u8> {
    let hs_len = body.len();
    let total = 5 + 4 + hs_len;
    let mut buf = Vec::with_capacity(total);
    buf.push(0x16); // ContentType: Handshake
    buf.extend_from_slice(&record_version);
    let hs_with_header_len = (4 + hs_len) as u16;
    buf.extend_from_slice(&hs_with_header_len.to_be_bytes());
    buf.push(hs_type);
    buf.push(((hs_len >> 16) & 0xff) as u8);
    buf.push(((hs_len >> 8) & 0xff) as u8);
    buf.push((hs_len & 0xff) as u8);
    buf.extend_from_slice(body);
    buf
}

pub fn build_tls_client_hello(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();

    const GREASE_VALUES: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let grease_idx: u8 = rand::random::<u8>() % GREASE_VALUES.len() as u8;
    let grease = GREASE_VALUES[grease_idx as usize];
    let grease_bytes = grease.to_be_bytes();
    let grease2_idx: u8 = (grease_idx + 1) % GREASE_VALUES.len() as u8;
    let grease2 = GREASE_VALUES[grease2_idx as usize];
    let grease2_bytes = grease2.to_be_bytes();

    let mut extensions = Vec::with_capacity(512);

    // 1. GREASE extension
    extensions.extend_from_slice(&grease_bytes);
    extensions.extend_from_slice(&[0x00, 0x00]);

    // 2. SNI (0x0000)
    let sni_name_len = host_bytes.len();
    let sni_list_len = 1 + 2 + sni_name_len;
    let sni_ext_data_len = 2 + sni_list_len;
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(sni_name_len as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    // 3. extended_master_secret (0x0017)
    extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // 4. renegotiation_info (0xff01)
    extensions.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // 5. supported_groups (0x000a)
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a]);
    extensions.extend_from_slice(&grease_bytes);
    extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1
    extensions.extend_from_slice(&[0x00, 0x18]); // secp384r1
    extensions.extend_from_slice(&[0x00, 0x19]); // secp521r1

    // 6. ec_point_formats (0x000b)
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    // 7. session_ticket (0x0023)
    extensions.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    // 8. status_request / OCSP (0x0005)
    extensions.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);

    // 9. signature_algorithms (0x000d)
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x12, 0x00, 0x10]);
    extensions.extend_from_slice(&[0x04, 0x03]); // ecdsa_secp256r1_sha256
    extensions.extend_from_slice(&[0x08, 0x04]); // rsa_pss_rsae_sha256
    extensions.extend_from_slice(&[0x04, 0x01]); // rsa_pkcs1_sha256
    extensions.extend_from_slice(&[0x05, 0x03]); // ecdsa_secp384r1_sha384
    extensions.extend_from_slice(&[0x08, 0x05]); // rsa_pss_rsae_sha384
    extensions.extend_from_slice(&[0x05, 0x01]); // rsa_pkcs1_sha384
    extensions.extend_from_slice(&[0x08, 0x06]); // rsa_pss_rsae_sha512
    extensions.extend_from_slice(&[0x06, 0x01]); // rsa_pkcs1_sha512

    // 10. signed_certificate_timestamp (0x0012)
    extensions.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);

    // 11. ALPN (0x0010)
    let alpn_protocols: &[&[u8]] = &[b"h2", b"http/1.1"];
    let alpn_list_len: usize = alpn_protocols.iter().map(|p| 1 + p.len()).sum();
    let alpn_ext_data_len = 2 + alpn_list_len;
    extensions.extend_from_slice(&[0x00, 0x10]);
    extensions.extend_from_slice(&(alpn_ext_data_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
    for proto in alpn_protocols {
        extensions.push(proto.len() as u8);
        extensions.extend_from_slice(proto);
    }

    // 12. compress_certificate (0x001b) - brotli
    extensions.extend_from_slice(&[0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02]);

    // 13. application_settings / ALPS (0x4469) - h2
    extensions.extend_from_slice(&[0x44, 0x69, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32]);

    // 14. supported_versions (0x002b) - TLS 1.3 + 1.2
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x07, 0x06]);
    extensions.extend_from_slice(&grease_bytes);
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    extensions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // 15. key_share (0x0033) - GREASE entry + x25519
    let fake_pubkey: [u8; 32] = rand::random();
    let grease_ks_data: [u8; 1] = rand::random();
    let key_share_list_len: u16 = 5 + 36;
    let key_share_ext_len: u16 = 2 + key_share_list_len;
    extensions.extend_from_slice(&[0x00, 0x33]);
    extensions.extend_from_slice(&key_share_ext_len.to_be_bytes());
    extensions.extend_from_slice(&key_share_list_len.to_be_bytes());
    extensions.extend_from_slice(&grease2_bytes); // GREASE group
    extensions.extend_from_slice(&(1u16).to_be_bytes());
    extensions.extend_from_slice(&grease_ks_data);
    extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    extensions.extend_from_slice(&(32u16).to_be_bytes());
    extensions.extend_from_slice(&fake_pubkey);

    // 16. psk_key_exchange_modes (0x002d)
    extensions.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

    // 17. Second GREASE extension
    extensions.extend_from_slice(&grease2_bytes);
    extensions.extend_from_slice(&[0x00, 0x01, 0x00]);

    // ClientHello body
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    body.push(0x20); // session_id_len = 32
    let session_id: [u8; 32] = rand::random();
    body.extend_from_slice(&session_id);
    // Cipher suites
    body.extend_from_slice(&[0x00, 0x10]);
    body.extend_from_slice(&grease_bytes);
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
    body.extend_from_slice(&[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256
    body.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0xc0, 0x2c]); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    body.extend_from_slice(&[0xc0, 0x30]); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    // Compression
    body.extend_from_slice(&[0x01, 0x00]);

    // 18. padding (0x0015) - pad to 512-byte boundary
    let body_without_ext = body.len();
    let current_total = body_without_ext + 2 + extensions.len();
    let target_len = 512usize;
    if current_total < target_len {
        let pad_data_len = target_len - current_total - 4;
        if pad_data_len > 0 {
            extensions.extend_from_slice(&[0x00, 0x15]);
            extensions.extend_from_slice(&(pad_data_len as u16).to_be_bytes());
            extensions.resize(extensions.len() + pad_data_len, 0x00);
        }
    }

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    wrap_tls_handshake(0x01, &body, [0x03, 0x01])
}

pub fn build_tls_server_hello(client_session_id: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    if let Some(sid) = client_session_id {
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
    } else {
        body.push(0x20);
        let session_id: [u8; 32] = rand::random();
        body.extend_from_slice(&session_id);
    }
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0x00); // compression: null

    let mut extensions = Vec::new();
    // supported_versions (0x002b) - TLS 1.3
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    // key_share (0x0033) - server x25519
    let server_pubkey: [u8; 32] = rand::random();
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    extensions.extend_from_slice(&server_pubkey);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    wrap_tls_handshake(0x02, &body, [0x03, 0x03])
}

pub fn build_fake_server_encrypted_handshake() -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    // ChangeCipherSpec
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    // Fake encrypted handshake records (reduced size for faketcp compatibility)
    let r1_len = 200 + (rand::random::<u16>() % 200) as usize;
    let r2_len = 100 + (rand::random::<u16>() % 100) as usize;
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(r1_len as u16).to_be_bytes());
    let start = out.len();
    out.resize(start + r1_len, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(r2_len as u16).to_be_bytes());
    let start = out.len();
    out.resize(start + r2_len, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
    out
}

pub fn build_fake_client_finished() -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    // Client ChangeCipherSpec
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    // Client Finished
    let finished_len = 36 + (rand::random::<u8>() % 20) as usize;
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(finished_len as u16).to_be_bytes());
    let start = out.len();
    out.resize(start + finished_len, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
    out
}

// --- HTTP/WebSocket handshake builders ---

pub fn compute_ws_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_MAGIC.as_bytes());
    BASE64_STANDARD.encode(hasher.finalize())
}

pub fn build_http_request(host: &str) -> (Vec<u8>, String) {
    let ws_key: [u8; 16] = rand::random();
    let ws_key_b64 = BASE64_STANDARD.encode(ws_key);
    let req = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36\r\n\
         Upgrade: websocket\r\n\
         Origin: http://{host}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\
         Sec-WebSocket-Key: {ws_key_b64}\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         \r\n"
    )
    .into_bytes();
    (req, ws_key_b64)
}

pub fn build_http_response(ws_accept: &str) -> Vec<u8> {
    let date_str = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {ws_accept}\r\n\
         Server: nginx/1.24.0\r\n\
         Date: {date_str}\r\n\
         \r\n"
    )
    .into_bytes()
}

pub fn extract_ws_key(headers: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        if let Some(colon_pos) = line.find(':') {
            let name = &line[..colon_pos];
            if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                return Some(line[colon_pos + 1..].trim());
            }
        }
    }
    None
}

// --- Data frame encode/decode (pure functions) ---
// These are used when faketcp raw disguise is integrated at the packet level.
// Currently fakehttp uses AsyncRead/AsyncWrite stream adapters instead.

#[allow(dead_code)]
pub fn encode_tls_record(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut buf = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + len);
    buf.extend_from_slice(&[0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]);
    buf.extend_from_slice(payload);
    buf
}

/// Decode a TLS Application Data record from the beginning of `buf`.
/// Returns `(consumed_bytes, payload_slice)` or `None` if incomplete.
#[allow(dead_code)]
pub fn decode_tls_record(buf: &[u8]) -> Option<(usize, &[u8])> {
    if buf.len() < TLS_RECORD_HEADER_SIZE {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = TLS_RECORD_HEADER_SIZE + record_len;
    if buf.len() < total {
        return None;
    }
    Some((total, &buf[TLS_RECORD_HEADER_SIZE..total]))
}

#[allow(dead_code)]
pub fn encode_ws_frame(payload: &[u8], is_client: bool) -> Vec<u8> {
    let payload_len = payload.len();
    let mask_len = if is_client { 4 } else { 0 };
    let header_len = 1 + if payload_len <= 125 {
        1
    } else if payload_len <= 65535 {
        3
    } else {
        9
    } + mask_len;

    let mut buf = Vec::with_capacity(header_len + payload_len);
    buf.push(0x82); // FIN + Binary opcode

    let mask_bit: u8 = if is_client { 0x80 } else { 0x00 };
    if payload_len <= 125 {
        buf.push(mask_bit | payload_len as u8);
    } else if payload_len <= 65535 {
        buf.push(mask_bit | 126);
        buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        buf.push(mask_bit | 127);
        buf.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    if is_client {
        let mask_key: [u8; 4] = rand::random();
        buf.extend_from_slice(&mask_key);
        let mask_u64 = u64::from_ne_bytes([
            mask_key[0], mask_key[1], mask_key[2], mask_key[3],
            mask_key[0], mask_key[1], mask_key[2], mask_key[3],
        ]);
        let chunks = payload.chunks_exact(8);
        let remainder = chunks.remainder();
        for chunk in chunks {
            let val = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ mask_u64;
            buf.extend_from_slice(&val.to_ne_bytes());
        }
        for (i, &b) in remainder.iter().enumerate() {
            buf.push(b ^ mask_key[(payload_len - remainder.len() + i) % 4]);
        }
    } else {
        buf.extend_from_slice(payload);
    }

    buf
}

/// Decode a WebSocket binary frame from `buf`.
/// Returns `(consumed_bytes, unmasked_payload)` or `None` if incomplete.
#[allow(dead_code)]
pub fn decode_ws_frame(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
    if buf.len() < 2 {
        return None;
    }

    let has_mask = (buf[1] & 0x80) != 0;
    let len_code = (buf[1] & 0x7F) as usize;

    let (payload_len, header_base) = match len_code {
        0..=125 => (len_code, 2),
        126 => {
            if buf.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        }
        _ => {
            if buf.len() < 10 {
                return None;
            }
            (
                u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                10,
            )
        }
    };

    let mask_len = if has_mask { 4 } else { 0 };
    let total_header = header_base + mask_len;
    let total = total_header + payload_len;

    if buf.len() < total {
        return None;
    }

    let payload_start = total_header;
    let payload_bytes = &buf[payload_start..payload_start + payload_len];

    let payload = if has_mask {
        let mask_key = &buf[header_base..header_base + 4];
        let mask_u64 = u64::from_ne_bytes([
            mask_key[0], mask_key[1], mask_key[2], mask_key[3],
            mask_key[0], mask_key[1], mask_key[2], mask_key[3],
        ]);
        let mut out = Vec::with_capacity(payload_len);
        let chunks = payload_bytes.chunks_exact(8);
        let remainder = chunks.remainder();
        for chunk in chunks {
            let val = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ mask_u64;
            out.extend_from_slice(&val.to_ne_bytes());
        }
        for (i, &b) in remainder.iter().enumerate() {
            out.push(b ^ mask_key[(payload_len - remainder.len() + i) % 4]);
        }
        out
    } else {
        payload_bytes.to_vec()
    };

    Some((total, payload))
}

#[allow(dead_code)]
pub fn ws_frame_overhead(payload_len: usize, is_client: bool) -> usize {
    let len_bytes = if payload_len <= 125 {
        1
    } else if payload_len <= 65535 {
        3
    } else {
        9
    };
    let mask_bytes = if is_client { 4 } else { 0 };
    1 + len_bytes + mask_bytes // opcode + len + mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_record_roundtrip() {
        let data = b"hello world, this is a test payload";
        let encoded = encode_tls_record(data);
        assert_eq!(encoded[0], 0x17);
        assert_eq!(encoded[1], 0x03);
        assert_eq!(encoded[2], 0x03);
        let (consumed, decoded) = decode_tls_record(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn ws_frame_roundtrip_unmasked() {
        let data = b"test payload for ws frame";
        let encoded = encode_ws_frame(data, false);
        let (consumed, decoded) = decode_ws_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn ws_frame_roundtrip_masked() {
        let data = b"masked payload for ws frame testing with some extra length";
        let encoded = encode_ws_frame(data, true);
        let (consumed, decoded) = decode_ws_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn ws_frame_extended_length() {
        let data = vec![0xAB; 300];
        let encoded = encode_ws_frame(&data, true);
        let (consumed, decoded) = decode_ws_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn tls_client_hello_structure() {
        let hello = build_tls_client_hello("www.example.com");
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01); // TLS 1.0 record version
        // Handshake type ClientHello
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn tls_server_hello_structure() {
        let hello = build_tls_server_hello(Some(&[0u8; 32]));
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x03); // TLS 1.2 record version
        assert_eq!(hello[5], 0x02); // ServerHello type
    }

    #[test]
    fn ws_accept_computation() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_ws_accept(key);
        // SHA1("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-5AB5DC30CE87") base64
        assert_eq!(accept, "vu2or8FcdSt/9u+gA0rtwZV0Moo=");
    }

    #[test]
    fn decode_incomplete_tls_record() {
        assert_eq!(decode_tls_record(&[0x17, 0x03, 0x03]), None);
        assert_eq!(decode_tls_record(&[0x17, 0x03, 0x03, 0x00, 0x05, 0x01]), None);
    }

    #[test]
    fn decode_incomplete_ws_frame() {
        assert_eq!(decode_ws_frame(&[0x82]), None);
        assert_eq!(decode_ws_frame(&[0x82, 0x05, 0x01]), None);
    }
}
