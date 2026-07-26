use bytes::BytesMut;
use std::sync::Arc;

use crate::tunnel::disguise_protocol;

use super::stack;

#[derive(Clone, Debug)]
pub enum DisguiseMode {
    Off,
    Tls { host: String },
    Http { host: String },
}

const DATA_LEN_PREFIX_SIZE: usize = 2; // u16 LE length prefix inside the frame

impl DisguiseMode {
    pub fn max_overhead(&self, is_client: bool) -> usize {
        match self {
            DisguiseMode::Off => 0,
            DisguiseMode::Tls { .. } => {
                disguise_protocol::TLS_RECORD_HEADER_SIZE + DATA_LEN_PREFIX_SIZE
            }
            DisguiseMode::Http { .. } => {
                disguise_protocol::ws_frame_overhead(1400, is_client) + DATA_LEN_PREFIX_SIZE
            }
        }
    }
}

pub fn parse_disguise_mode(hosts: &[String]) -> DisguiseMode {
    let entry = match hosts.first() {
        Some(e) => e,
        None => return DisguiseMode::Off,
    };
    if let Some(host) = entry.strip_prefix("https://") {
        DisguiseMode::Tls {
            host: host.to_string(),
        }
    } else if let Some(host) = entry.strip_prefix("http://") {
        DisguiseMode::Http {
            host: host.to_string(),
        }
    } else {
        tracing::warn!(entry = %entry, "faketcp disguise: unsupported entry, expected http:// or https://");
        DisguiseMode::Off
    }
}

const HANDSHAKE_TIMEOUT_MS: u64 = 5000;

pub async fn perform_client_handshake(
    socket: &Arc<stack::Socket>,
    mode: &DisguiseMode,
) -> Result<(), crate::tunnel::TunnelError> {
    match mode {
        DisguiseMode::Off => Ok(()),
        DisguiseMode::Tls { host } => {
            let client_hello = disguise_protocol::build_tls_client_hello(host);
            send_chunks(socket, &client_hello);

            // Receive server response (ServerHello + CCS + encrypted records)
            let mut buf = BytesMut::new();
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS);
            drain_handshake_records(socket, &mut buf, 4, deadline).await?;

            // Send client CCS + Finished
            let finished = disguise_protocol::build_fake_client_finished();
            send_chunks(socket, &finished);
            Ok(())
        }
        DisguiseMode::Http { host } => {
            let (request, _ws_key) = disguise_protocol::build_http_request(host);
            send_chunks(socket, &request);

            // Receive HTTP 101 response
            let mut buf = BytesMut::new();
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS);
            loop {
                match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(crate::tunnel::TunnelError::InternalError(
                            "faketcp disguise: connection closed during HTTP handshake".into(),
                        ));
                    }
                    Err(_) => {
                        return Err(crate::tunnel::TunnelError::InternalError(
                            "faketcp disguise: HTTP handshake timeout".into(),
                        ));
                    }
                }
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 4096 {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: HTTP response too large".into(),
                    ));
                }
            }
            Ok(())
        }
    }
}

pub async fn perform_server_handshake(
    socket: &Arc<stack::Socket>,
    mode: &DisguiseMode,
) -> Result<(), crate::tunnel::TunnelError> {
    match mode {
        DisguiseMode::Off => Ok(()),
        DisguiseMode::Tls { .. } => {
            let mut buf = BytesMut::new();
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS);

            // Receive ClientHello (1 TLS record) — keep data for session_id extraction
            recv_full_record(socket, &mut buf, deadline).await?;

            // Parse session_id from the complete record data
            let session_id = extract_session_id_from_record(&buf);

            // Send ServerHello + CCS + fake encrypted handshake
            let server_hello = disguise_protocol::build_tls_server_hello(session_id);
            let fake_hs = disguise_protocol::build_fake_server_encrypted_handshake();
            let mut combined = Vec::with_capacity(server_hello.len() + fake_hs.len());
            combined.extend_from_slice(&server_hello);
            combined.extend_from_slice(&fake_hs);
            send_chunks(socket, &combined);

            // Drain client CCS + Finished (2 records)
            buf.clear();
            drain_handshake_records(socket, &mut buf, 2, deadline).await?;

            Ok(())
        }
        DisguiseMode::Http { .. } => {
            let mut buf = BytesMut::new();
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS);

            // Receive HTTP upgrade request
            loop {
                match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(crate::tunnel::TunnelError::InternalError(
                            "faketcp disguise: connection closed during HTTP handshake".into(),
                        ));
                    }
                    Err(_) => {
                        return Err(crate::tunnel::TunnelError::InternalError(
                            "faketcp disguise: HTTP handshake timeout".into(),
                        ));
                    }
                }
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 8192 {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: HTTP request too large".into(),
                    ));
                }
            }

            // Extract WS key and send 101 response
            let ws_accept = disguise_protocol::extract_ws_key(&buf)
                .map(|key| disguise_protocol::compute_ws_accept(key))
                .unwrap_or_default();
            let response = disguise_protocol::build_http_response(&ws_accept);
            send_chunks(socket, &response);

            Ok(())
        }
    }
}

/// Wrap payload with disguise framing.
///
/// A 2-byte little-endian length prefix inside the frame tells the receiver
/// how many data bytes to extract.
pub fn wrap_payload(mode: &DisguiseMode, payload: &[u8], is_client: bool) -> Vec<u8> {
    match mode {
        DisguiseMode::Off => payload.to_vec(),
        DisguiseMode::Tls { .. } => {
            let inner_len = DATA_LEN_PREFIX_SIZE + payload.len();
            let mut buf =
                Vec::with_capacity(disguise_protocol::TLS_RECORD_HEADER_SIZE + inner_len);
            buf.extend_from_slice(&[
                0x17,
                0x03,
                0x03,
                (inner_len >> 8) as u8,
                inner_len as u8,
            ]);
            buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }
        DisguiseMode::Http { .. } => {
            let inner_len = DATA_LEN_PREFIX_SIZE + payload.len();
            let mut inner = Vec::with_capacity(inner_len);
            inner.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            inner.extend_from_slice(payload);
            disguise_protocol::encode_ws_frame(&inner, is_client)
        }
    }
}

/// Unwrap payload from disguise framing, stripping the built-in padding.
/// Returns the actual data, or None on parse error.
pub fn unwrap_payload(mode: &DisguiseMode, data: &[u8]) -> Option<Vec<u8>> {
    match mode {
        DisguiseMode::Off => Some(data.to_vec()),
        DisguiseMode::Tls { .. } => {
            let (_consumed, inner) = disguise_protocol::decode_tls_record(data)?;
            extract_data_from_inner(inner)
        }
        DisguiseMode::Http { .. } => {
            let (_consumed, inner) = disguise_protocol::decode_ws_frame(data)?;
            extract_data_from_inner(&inner)
        }
    }
}

fn extract_data_from_inner(inner: &[u8]) -> Option<Vec<u8>> {
    if inner.len() < 2 {
        return None;
    }
    let data_len = u16::from_le_bytes([inner[0], inner[1]]) as usize;
    if inner.len() < 2 + data_len {
        return None;
    }
    Some(inner[2..2 + data_len].to_vec())
}

// --- Internal helpers ---

const MAX_CHUNK_SIZE: usize = 1400;

fn send_chunks(socket: &Arc<stack::Socket>, data: &[u8]) {
    for chunk in data.chunks(MAX_CHUNK_SIZE) {
        socket.build_packet(chunk).map(|frame| {
            let _ = socket.flush_batch(&[frame]);
        });
    }
}

async fn recv_full_record(
    socket: &Arc<stack::Socket>,
    buf: &mut BytesMut,
    deadline: tokio::time::Instant,
) -> Result<(), crate::tunnel::TunnelError> {
    while buf.len() < 5 {
        match tokio::time::timeout_at(deadline, socket.recv(buf)).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(crate::tunnel::TunnelError::InternalError(
                    "faketcp disguise: connection closed during TLS handshake".into(),
                ));
            }
            Err(_) => {
                return Err(crate::tunnel::TunnelError::InternalError(
                    "faketcp disguise: TLS handshake timeout".into(),
                ));
            }
        }
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total_needed = 5 + record_len;
    while buf.len() < total_needed {
        match tokio::time::timeout_at(deadline, socket.recv(buf)).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(crate::tunnel::TunnelError::InternalError(
                    "faketcp disguise: connection closed during TLS handshake".into(),
                ));
            }
            Err(_) => {
                return Err(crate::tunnel::TunnelError::InternalError(
                    "faketcp disguise: TLS handshake timeout".into(),
                ));
            }
        }
    }
    Ok(())
}

async fn drain_handshake_records(
    socket: &Arc<stack::Socket>,
    buf: &mut BytesMut,
    count: usize,
    deadline: tokio::time::Instant,
) -> Result<(), crate::tunnel::TunnelError> {
    let mut drained = 0;
    while drained < count {
        // Ensure we have at least a TLS record header
        while buf.len() < 5 {
            match tokio::time::timeout_at(deadline, socket.recv(buf)).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: connection closed during TLS handshake".into(),
                    ));
                }
                Err(_) => {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: TLS handshake timeout".into(),
                    ));
                }
            }
        }

        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total_needed = 5 + record_len;

        // Read remaining bytes for this record
        while buf.len() < total_needed {
            match tokio::time::timeout_at(deadline, socket.recv(buf)).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: connection closed during TLS handshake".into(),
                    ));
                }
                Err(_) => {
                    return Err(crate::tunnel::TunnelError::InternalError(
                        "faketcp disguise: TLS handshake timeout".into(),
                    ));
                }
            }
        }

        // Consume this record from the buffer
        let _ = buf.split_to(total_needed);
        drained += 1;
    }
    Ok(())
}

fn extract_session_id_from_record(record_data: &[u8]) -> Option<&[u8]> {
    // TLS record: content_type(1) + version(2) + length(2) + body
    // Handshake body: hs_type(1) + length(3) + version(2) + random(32) + session_id_len(1)
    // Offset into record_data: 5 (record header) + 1 + 3 + 2 + 32 = 43
    if record_data.len() <= 43 {
        return None;
    }
    let sid_len = record_data[43] as usize;
    if record_data.len() < 44 + sid_len {
        return None;
    }
    Some(&record_data[44..44 + sid_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_disguise_mode_tls() {
        let hosts = vec!["https://www.google.com".to_string()];
        match parse_disguise_mode(&hosts) {
            DisguiseMode::Tls { host } => assert_eq!(host, "www.google.com"),
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn parse_disguise_mode_http() {
        let hosts = vec!["http://example.com".to_string()];
        match parse_disguise_mode(&hosts) {
            DisguiseMode::Http { host } => assert_eq!(host, "example.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_disguise_mode_empty() {
        let hosts: Vec<String> = vec![];
        assert!(matches!(parse_disguise_mode(&hosts), DisguiseMode::Off));
    }

    #[test]
    fn wrap_unwrap_tls() {
        let mode = DisguiseMode::Tls {
            host: "test.com".into(),
        };
        let data = b"hello world test data";
        let wrapped = wrap_payload(&mode, data, true);
        let unwrapped = unwrap_payload(&mode, &wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn wrap_unwrap_tls_large_payload() {
        let mode = DisguiseMode::Tls {
            host: "test.com".into(),
        };
        let data = vec![0xAB; 1000];
        let wrapped = wrap_payload(&mode, &data, true);
        let unwrapped = unwrap_payload(&mode, &wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn wrap_unwrap_ws_client() {
        let mode = DisguiseMode::Http {
            host: "ws.example.com".into(),
        };
        let data = b"websocket payload data for testing";
        let wrapped = wrap_payload(&mode, data, true);
        let unwrapped = unwrap_payload(&mode, &wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn wrap_unwrap_ws_server() {
        let mode = DisguiseMode::Http {
            host: "ws.example.com".into(),
        };
        let data = b"server side ws payload";
        let wrapped = wrap_payload(&mode, data, false);
        let unwrapped = unwrap_payload(&mode, &wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn disguise_off_passthrough() {
        let mode = DisguiseMode::Off;
        let data = b"raw data no disguise";
        let wrapped = wrap_payload(&mode, data, true);
        assert_eq!(wrapped, data);
        let unwrapped = unwrap_payload(&mode, &wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }
}
