use bytes::BytesMut;

use super::stack;
use crate::tunnel::TunnelError;

const TLS_RECORD_HEADER_LEN: usize = 5;
pub const TLS_APP_DATA_TYPE: u8 = 0x17;
const TLS_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_MAX_RECORD_LEN: usize = 16384; // TLS record max payload per RFC 8446

pub fn wrap_tls_record(payload: &[u8]) -> Vec<u8> {
    let len = payload.len().min(TLS_MAX_RECORD_LEN);
    let mut buf = Vec::with_capacity(TLS_RECORD_HEADER_LEN + len);
    buf.push(TLS_APP_DATA_TYPE);
    buf.extend_from_slice(&TLS_VERSION);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&payload[..len]);
    buf
}

pub fn strip_tls_record_header(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return None;
    }
    // Accept TLS Application Data (0x17) and also TLS version 0x0301/0x0303
    if buf[0] != TLS_APP_DATA_TYPE || buf[1] != 0x03 {
        return None;
    }
    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    Some((TLS_RECORD_HEADER_LEN, payload_len))
}

fn build_change_cipher_spec() -> Vec<u8> {
    vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
}

pub async fn client_tls_handshake(
    socket: &stack::Socket,
    host: &str,
) -> Result<(), TunnelError> {
    #[cfg(feature = "fakehttp")]
    {
        let hello = crate::tunnel::fakehttp::build_tls_client_hello(host);
        socket.try_send(&hello).ok_or(TunnelError::InternalError(
            "TLS disguise: failed to send ClientHello".into(),
        ))?;

        // Receive ServerHello (may include ChangeCipherSpec in same recv)
        let mut buf = BytesMut::new();
        socket.recv(&mut buf).await.ok_or(TunnelError::InternalError(
            "TLS disguise: failed to receive ServerHello".into(),
        ))?;
        if buf.first() != Some(&0x16) {
            return Err(TunnelError::InternalError(
                "TLS disguise: invalid ServerHello response".into(),
            ));
        }

        // Server may send CCS as a separate packet — drain it if it arrives
        // We use a short timeout to avoid blocking if it was already bundled above
        let mut ccs_buf = BytesMut::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.recv(&mut ccs_buf),
        )
        .await;

        // Client sends its own ChangeCipherSpec
        socket.try_send(&build_change_cipher_spec()).ok_or(
            TunnelError::InternalError(
                "TLS disguise: failed to send client ChangeCipherSpec".into(),
            ),
        )?;

        Ok(())
    }
    #[cfg(not(feature = "fakehttp"))]
    {
        let _ = (socket, host);
        Err(TunnelError::InternalError(
            "TLS disguise requires fakehttp feature".into(),
        ))
    }
}

pub async fn server_tls_handshake(socket: &stack::Socket) -> Result<(), TunnelError> {
    #[cfg(feature = "fakehttp")]
    {
        let mut buf = BytesMut::new();
        socket.recv(&mut buf).await.ok_or(TunnelError::InternalError(
            "TLS disguise: failed to receive ClientHello".into(),
        ))?;
        if buf.first() != Some(&0x16) {
            return Err(TunnelError::InternalError(
                "TLS disguise: invalid ClientHello".into(),
            ));
        }

        // Parse session_id from ClientHello:
        // record_header(5) + handshake_type(1) + length(3) + version(2) + random(32) + sid_len(1)
        let session_id = if buf.len() > 44 {
            let sid_len = buf[43] as usize;
            if buf.len() >= 44 + sid_len {
                Some(&buf[44..44 + sid_len])
            } else {
                None
            }
        } else {
            None
        };

        let server_hello = crate::tunnel::fakehttp::build_tls_server_hello(session_id);
        let ccs = build_change_cipher_spec();
        let mut combined = Vec::with_capacity(server_hello.len() + ccs.len());
        combined.extend_from_slice(&server_hello);
        combined.extend_from_slice(&ccs);
        socket.try_send(&combined).ok_or(TunnelError::InternalError(
            "TLS disguise: failed to send ServerHello+CCS".into(),
        ))?;

        // Wait for client's ChangeCipherSpec
        let mut ccs_buf = BytesMut::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            socket.recv(&mut ccs_buf),
        )
        .await;

        Ok(())
    }
    #[cfg(not(feature = "fakehttp"))]
    {
        let _ = socket;
        Err(TunnelError::InternalError(
            "TLS disguise requires fakehttp feature".into(),
        ))
    }
}
