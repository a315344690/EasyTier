use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use futures::stream::FuturesUnordered;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{Duration, timeout};

use super::{
    FromUrl, IpVersion, Tunnel, TunnelError, TunnelListener,
    common::{FramedReader, FramedWriter, TunnelWrapper, bind, wait_for_connect_futures},
};
use crate::tunnel::TunnelInfo;
use crate::tunnel::common::apply_socket_mark;

const TCP_MTU_BYTES: usize = 2000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-5AB5DC30CE87";

// --- Payload types ---

#[derive(Debug, Clone)]
enum FakeHttpPayload {
    Http { host: String },
    Https { host: String },
}

impl FakeHttpPayload {
    fn client_bytes(&self) -> (Vec<u8>, Option<String>) {
        match self {
            Self::Http { host } => {
                let (req, key) = build_http_request(host);
                (req, Some(key))
            }
            Self::Https { host } => (build_tls_client_hello(host), None),
        }
    }
}

fn parse_payloads(hosts: Vec<String>) -> Vec<FakeHttpPayload> {
    let mut payloads = Vec::new();
    for entry in hosts {
        if let Some(host) = entry.strip_prefix("http://") {
            payloads.push(FakeHttpPayload::Http {
                host: host.to_string(),
            });
        } else if let Some(host) = entry.strip_prefix("https://") {
            payloads.push(FakeHttpPayload::Https {
                host: host.to_string(),
            });
        } else {
            tracing::warn!(entry = %entry, "fakehttp: unsupported entry (must start with http:// or https://), skipping");
        }
    }
    payloads
}

// --- Protocol builders ---

fn compute_ws_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_MAGIC.as_bytes());
    BASE64_STANDARD.encode(hasher.finalize())
}

fn build_http_request(host: &str) -> (Vec<u8>, String) {
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

fn build_http_response(ws_accept: &str) -> Vec<u8> {
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

/// Wrap a handshake body in TLS record + handshake headers.
/// `hs_type`: 0x01 = ClientHello, 0x02 = ServerHello
/// `record_version`: protocol version in the record layer header
pub(crate) fn wrap_tls_handshake(hs_type: u8, body: &[u8], record_version: [u8; 2]) -> Vec<u8> {
    let hs_len = body.len();
    // Handshake: type(1) + length(3, uint24) + body
    // Record:    content_type(1) + version(2) + length(2) + handshake
    let total = 5 + 4 + hs_len;
    let mut buf = Vec::with_capacity(total);
    // TLS record header
    buf.push(0x16); // ContentType: Handshake
    buf.extend_from_slice(&record_version);
    let hs_with_header_len = (4 + hs_len) as u16;
    buf.extend_from_slice(&hs_with_header_len.to_be_bytes());
    // Handshake header
    buf.push(hs_type);
    buf.push(((hs_len >> 16) & 0xff) as u8);
    buf.push(((hs_len >> 8) & 0xff) as u8);
    buf.push((hs_len & 0xff) as u8);
    // Handshake body
    buf.extend_from_slice(body);
    buf
}

pub(crate) fn build_tls_client_hello(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();

    const GREASE_VALUES: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let grease_idx: u8 = rand::random::<u8>() % GREASE_VALUES.len() as u8;
    let grease = GREASE_VALUES[grease_idx as usize];
    let grease_bytes = grease.to_be_bytes();
    // Second GREASE for key_share and trailing extension
    let grease2_idx: u8 = (grease_idx + 1) % GREASE_VALUES.len() as u8;
    let grease2 = GREASE_VALUES[grease2_idx as usize];
    let grease2_bytes = grease2.to_be_bytes();

    // Extensions ordered to match Chrome 131
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
    // GREASE entry: group(2) + key_len(2) + key(1) = 5 bytes
    // x25519 entry: group(2) + key_len(2) + key(32) = 36 bytes
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

    // 17. Second GREASE extension (Chrome places one before padding)
    extensions.extend_from_slice(&grease2_bytes);
    extensions.extend_from_slice(&[0x00, 0x01, 0x00]);

    // ClientHello body (before padding calculation)
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    body.push(0x20); // session_id_len = 32
    let session_id: [u8; 32] = rand::random();
    body.extend_from_slice(&session_id);
    // Cipher suites (GREASE + 3 TLS1.3 + 4 TLS1.2 ECDHE = 8 suites = 16 bytes)
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
        let pad_data_len = target_len - current_total - 4; // -4 for ext_type(2) + ext_len(2)
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

pub(crate) fn build_tls_server_hello(client_session_id: Option<&[u8]>) -> Vec<u8> {
    // TLS 1.3 ServerHello: legacy_version=0x0303, negotiated version in supported_versions ext
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version (always 0x0303 in TLS 1.3)
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    // Echo client session_id (TLS 1.3 compatibility mode)
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

    // TLS 1.3 ServerHello extensions
    let mut extensions = Vec::new();
    // supported_versions (0x002b) - negotiated TLS 1.3
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    // key_share (0x0033) - server's x25519 public key (fake)
    let server_pubkey: [u8; 32] = rand::random();
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    extensions.extend_from_slice(&server_pubkey);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    wrap_tls_handshake(0x02, &body, [0x03, 0x03])
}

// --- TLS Application Data record IO adapters ---
// Wraps all post-handshake data in TLS Application Data records (0x17 0x03 0x03)
// so DPI sees continuous TLS traffic after the handshake.

const TLS_RECORD_HEADER_SIZE: usize = 5;
const TLS_MAX_PLAINTEXT: usize = 16384;

struct TlsRecordWriter<W> {
    inner: W,
    send_buf: Vec<u8>,
    send_pos: usize,
    payload_len: usize, // how many payload bytes are in current send_buf
}

impl<W> TlsRecordWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            send_buf: Vec::new(),
            send_pos: 0,
            payload_len: 0,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TlsRecordWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;

        // If we have a pending record, flush it
        if !me.send_buf.is_empty() {
            while me.send_pos < me.send_buf.len() {
                match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_pos..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "TLS record write: zero bytes",
                        )));
                    }
                    Poll::Ready(Ok(n)) => me.send_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Fully flushed — report how many payload bytes we consumed
            let n = me.payload_len;
            me.send_buf.clear();
            me.send_pos = 0;
            me.payload_len = 0;
            return Poll::Ready(Ok(n));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Build a new TLS Application Data record
        let chunk_len = buf.len().min(TLS_MAX_PLAINTEXT);
        me.send_buf.reserve(TLS_RECORD_HEADER_SIZE + chunk_len);
        me.send_buf
            .extend_from_slice(&[0x17, 0x03, 0x03, (chunk_len >> 8) as u8, chunk_len as u8]);
        me.send_buf.extend_from_slice(&buf[..chunk_len]);
        me.send_pos = 0;
        me.payload_len = chunk_len;

        // Try to write it all out
        while me.send_pos < me.send_buf.len() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS record write: zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => me.send_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        me.send_buf.clear();
        me.send_pos = 0;
        me.payload_len = 0;
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        while me.send_pos < me.send_buf.len() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS record flush: zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => me.send_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        me.send_buf.clear();
        me.send_pos = 0;
        me.payload_len = 0;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct TlsRecordReader<R> {
    inner: R,
    residual: Vec<u8>,
    residual_pos: usize,
    remaining_in_record: usize,
    hdr_buf: [u8; TLS_RECORD_HEADER_SIZE],
    hdr_len: usize,
}

impl<R> TlsRecordReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            residual: Vec::new(),
            residual_pos: 0,
            remaining_in_record: 0,
            hdr_buf: [0u8; TLS_RECORD_HEADER_SIZE],
            hdr_len: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TlsRecordReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;

        // 1. Serve residual data from a previous partial delivery
        if me.residual_pos < me.residual.len() {
            let to_copy = (me.residual.len() - me.residual_pos).min(buf.remaining());
            buf.put_slice(&me.residual[me.residual_pos..me.residual_pos + to_copy]);
            me.residual_pos += to_copy;
            if me.residual_pos >= me.residual.len() {
                me.residual.clear();
                me.residual_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 2. If mid-record, read payload into local buf then copy to caller
        if me.remaining_in_record > 0 {
            let to_read = me.remaining_in_record.min(buf.remaining());
            if to_read == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = [0u8; 4096];
            let read_len = to_read.min(tmp.len());
            let mut tmp_buf = ReadBuf::new(&mut tmp[..read_len]);
            match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "TLS record payload truncated",
                        )));
                    }
                    me.remaining_in_record -= n;
                    buf.put_slice(&tmp[..n]);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 3. Read raw data from socket
        let mut raw = [0u8; 4096];
        let mut raw_buf = ReadBuf::new(&mut raw);
        match Pin::new(&mut me.inner).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(())) => {
                let n = raw_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }

                let data = &raw[..n];
                let mut i = 0;

                // Complete a partial header from the previous read
                if me.hdr_len > 0 {
                    let need = TLS_RECORD_HEADER_SIZE - me.hdr_len;
                    let avail = data.len().min(need);
                    me.hdr_buf[me.hdr_len..me.hdr_len + avail]
                        .copy_from_slice(&data[..avail]);
                    me.hdr_len += avail;
                    i = avail;

                    if me.hdr_len < TLS_RECORD_HEADER_SIZE {
                        // Still not enough for a full header
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }

                    // Header now complete
                    if me.hdr_buf[0] == 0x17 && me.hdr_buf[1] == 0x03 {
                        me.remaining_in_record =
                            u16::from_be_bytes([me.hdr_buf[3], me.hdr_buf[4]]) as usize;
                    } else {
                        me.residual
                            .extend_from_slice(&me.hdr_buf[..TLS_RECORD_HEADER_SIZE]);
                    }
                    me.hdr_len = 0;
                }

                // Process the rest of the buffer
                while i < data.len() {
                    if me.remaining_in_record > 0 {
                        let take = me.remaining_in_record.min(data.len() - i);
                        me.residual.extend_from_slice(&data[i..i + take]);
                        me.remaining_in_record -= take;
                        i += take;
                    } else if i + TLS_RECORD_HEADER_SIZE <= data.len() {
                        if data[i] == 0x17 && data[i + 1] == 0x03 {
                            me.remaining_in_record =
                                u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
                            i += TLS_RECORD_HEADER_SIZE;
                        } else {
                            me.residual.extend_from_slice(&data[i..]);
                            i = data.len();
                        }
                    } else {
                        // Partial header at buffer boundary — stash it
                        let partial = data.len() - i;
                        me.hdr_buf[..partial].copy_from_slice(&data[i..]);
                        me.hdr_len = partial;
                        i = data.len();
                    }
                }

                // Deliver decoded payload
                if !me.residual.is_empty() {
                    let to_copy = me.residual.len().min(buf.remaining());
                    buf.put_slice(&me.residual[..to_copy]);
                    me.residual_pos = to_copy;
                    if me.residual_pos >= me.residual.len() {
                        me.residual.clear();
                        me.residual_pos = 0;
                    }
                    Poll::Ready(Ok(()))
                } else if me.remaining_in_record > 0 {
                    let to_read = me.remaining_in_record.min(buf.remaining());
                    if to_read == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let mut tmp2 = [0u8; 4096];
                    let read_len = to_read.min(tmp2.len());
                    let mut tmp2_buf = ReadBuf::new(&mut tmp2[..read_len]);
                    match Pin::new(&mut me.inner).poll_read(cx, &mut tmp2_buf) {
                        Poll::Ready(Ok(())) => {
                            let rd = tmp2_buf.filled().len();
                            me.remaining_in_record -= rd;
                            if rd > 0 {
                                buf.put_slice(&tmp2[..rd]);
                            }
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    // Rare: all data was just headers — retry
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}



// --- WebSocket Frame Writer/Reader ---
// Wraps data in RFC 6455 binary frames so post-101 traffic passes DPI frame checks.

struct WsFrameWriter<W> {
    inner: W,
    is_client: bool,
    send_buf: Vec<u8>,
    send_offset: usize,
    pending_payload_len: usize, // payload len of frame currently in send_buf
}

impl<W> WsFrameWriter<W> {
    fn new(inner: W, is_client: bool) -> Self {
        Self {
            inner,
            is_client,
            send_buf: Vec::with_capacity(TCP_MTU_BYTES + 14),
            send_offset: 0,
            pending_payload_len: 0,
        }
    }

    fn has_pending(&self) -> bool {
        self.send_offset < self.send_buf.len() && !self.send_buf.is_empty()
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for WsFrameWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;

        // If we have a pending frame, finish sending it first
        if me.has_pending() {
            loop {
                match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_offset..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "WS frame write: zero bytes written",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        me.send_offset += n;
                        if me.send_offset >= me.send_buf.len() {
                            let len = me.pending_payload_len;
                            me.send_buf.clear();
                            me.send_offset = 0;
                            me.pending_payload_len = 0;
                            return Poll::Ready(Ok(len));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Build WS binary frame into send_buf
        me.send_buf.clear();
        me.send_offset = 0;

        let payload_len = buf.len();
        me.send_buf.push(0x82); // FIN + Binary opcode

        let mask_bit: u8 = if me.is_client { 0x80 } else { 0x00 };
        if payload_len <= 125 {
            me.send_buf.push(mask_bit | payload_len as u8);
        } else if payload_len <= 65535 {
            me.send_buf.push(mask_bit | 126);
            me.send_buf
                .extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            me.send_buf.push(mask_bit | 127);
            me.send_buf
                .extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        if me.is_client {
            let mask_key: [u8; 4] = rand::random();
            me.send_buf.extend_from_slice(&mask_key);
            let mask_u64 = u64::from_ne_bytes([
                mask_key[0], mask_key[1], mask_key[2], mask_key[3],
                mask_key[0], mask_key[1], mask_key[2], mask_key[3],
            ]);
            me.send_buf.reserve(payload_len);
            let chunks = buf.chunks_exact(8);
            let remainder = chunks.remainder();
            for chunk in chunks {
                let val = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ mask_u64;
                me.send_buf.extend_from_slice(&val.to_ne_bytes());
            }
            for (i, &b) in remainder.iter().enumerate() {
                me.send_buf
                    .push(b ^ mask_key[(payload_len - remainder.len() + i) % 4]);
            }
        } else {
            me.send_buf.extend_from_slice(buf);
        }

        me.pending_payload_len = payload_len;

        // Try to write the entire frame
        loop {
            match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "WS frame write: zero bytes written",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    me.send_offset += n;
                    if me.send_offset >= me.send_buf.len() {
                        me.send_buf.clear();
                        me.send_offset = 0;
                        me.pending_payload_len = 0;
                        return Poll::Ready(Ok(payload_len));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        while me.send_offset < me.send_buf.len() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.send_buf[me.send_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "WS frame flush: zero bytes written",
                    )));
                }
                Poll::Ready(Ok(n)) => me.send_offset += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        me.send_buf.clear();
        me.send_offset = 0;
        me.pending_payload_len = 0;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum WsReadState {
    ReadingHeader,
    ReadingPayload,
}

struct WsFrameReader<R> {
    inner: R,
    state: WsReadState,
    hdr_buf: [u8; 14],
    hdr_len: usize,
    hdr_read: usize,
    remaining_payload: usize,
    mask_key: [u8; 4],
    has_mask: bool,
    mask_offset: usize,
    read_buf: Box<[u8; 4096]>,
}

impl<R> WsFrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: WsReadState::ReadingHeader,
            hdr_buf: [0u8; 14],
            hdr_len: 2,
            hdr_read: 0,
            remaining_payload: 0,
            mask_key: [0; 4],
            has_mask: false,
            mask_offset: 0,
            read_buf: Box::new([0u8; 4096]),
        }
    }

    fn reset_for_next_frame(&mut self) {
        self.state = WsReadState::ReadingHeader;
        self.hdr_len = 2;
        self.hdr_read = 0;
        self.remaining_payload = 0;
        self.has_mask = false;
        self.mask_offset = 0;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for WsFrameReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;

        loop {
            match me.state {
                WsReadState::ReadingHeader => {
                    // Read header bytes incrementally
                    while me.hdr_read < me.hdr_len {
                        let mut tmp = ReadBuf::new(&mut me.hdr_buf[me.hdr_read..me.hdr_len]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp.filled().len();
                                if n == 0 {
                                    return if me.hdr_read == 0 {
                                        Poll::Ready(Ok(())) // clean EOF
                                    } else {
                                        Poll::Ready(Err(std::io::Error::new(
                                            std::io::ErrorKind::UnexpectedEof,
                                            "incomplete WS frame header",
                                        )))
                                    };
                                }
                                me.hdr_read += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }

                        // After reading base 2 bytes, determine full header size
                        if me.hdr_read >= 2 && me.hdr_len == 2 {
                            let mask_bit = (me.hdr_buf[1] & 0x80) != 0;
                            let len_code = (me.hdr_buf[1] & 0x7F) as usize;
                            let ext_len = match len_code {
                                0..=125 => 0,
                                126 => 2,
                                _ => 8,
                            };
                            let mask_len = if mask_bit { 4 } else { 0 };
                            me.hdr_len = 2 + ext_len + mask_len;
                            // hdr_len now correct, loop continues reading remaining bytes
                        }
                    }

                    // Full header read — parse it
                    let mask_bit = (me.hdr_buf[1] & 0x80) != 0;
                    let len_code = (me.hdr_buf[1] & 0x7F) as usize;
                    let payload_len = match len_code {
                        0..=125 => len_code,
                        126 => u16::from_be_bytes([me.hdr_buf[2], me.hdr_buf[3]]) as usize,
                        _ => u64::from_be_bytes(
                            me.hdr_buf[2..10].try_into().unwrap(),
                        ) as usize,
                    };

                    me.has_mask = mask_bit;
                    if mask_bit {
                        let mask_start = 2 + match len_code {
                            0..=125 => 0,
                            126 => 2,
                            _ => 8,
                        };
                        me.mask_key.copy_from_slice(&me.hdr_buf[mask_start..mask_start + 4]);
                    }

                    me.remaining_payload = payload_len;
                    me.mask_offset = 0;

                    // Control frames (opcode >= 0x08): skip payload, read next frame
                    let opcode = me.hdr_buf[0] & 0x0F;
                    if opcode >= 0x08 {
                        if me.remaining_payload == 0 {
                            me.reset_for_next_frame();
                            continue;
                        }
                        // Drain control frame payload (max 125 bytes per RFC 6455)
                        let mut discard = [0u8; 125];
                        let to_drain = me.remaining_payload.min(125);
                        let mut tmp = ReadBuf::new(&mut discard[..to_drain]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "WS control frame truncated",
                                    )));
                                }
                                me.remaining_payload -= n;
                                if me.remaining_payload == 0 {
                                    me.reset_for_next_frame();
                                    continue;
                                }
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    if payload_len == 0 {
                        // Empty data frame — read next
                        me.reset_for_next_frame();
                        continue;
                    }

                    me.state = WsReadState::ReadingPayload;
                    // Fall through to payload reading
                }
                WsReadState::ReadingPayload => {
                    if me.remaining_payload == 0 {
                        me.reset_for_next_frame();
                        continue;
                    }

                    let to_read = me.remaining_payload.min(buf.remaining());
                    if to_read == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    if !me.has_mask {
                        // No mask: read directly into caller's buffer (zero-copy)
                        let before = buf.filled().len();
                        let dst = buf.initialize_unfilled_to(to_read);
                        let mut tmp_buf = ReadBuf::new(&mut dst[..to_read]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "WS frame payload truncated",
                                    )));
                                }
                                me.remaining_payload -= n;
                                me.mask_offset += n;
                                // Advance caller's buf by what we read
                                buf.set_filled(before + n);
                                return Poll::Ready(Ok(()));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        // Masked: read into internal buffer, unmask, then copy
                        let read_len = to_read.min(me.read_buf.len());
                        let mut tmp_buf = ReadBuf::new(&mut me.read_buf[..read_len]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "WS frame payload truncated",
                                    )));
                                }
                                me.remaining_payload -= n;
                                for i in 0..n {
                                    me.read_buf[i] ^= me.mask_key[me.mask_offset % 4];
                                    me.mask_offset += 1;
                                }
                                buf.put_slice(&me.read_buf[..n]);
                                return Poll::Ready(Ok(()));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
            }
        }
    }
}

// Fake TLS 1.3 post-handshake messages to complete the handshake appearance.
// In real TLS 1.3: ServerHello is followed by CCS + encrypted handshake records
// (EncryptedExtensions, Certificate, CertificateVerify, Finished).
fn build_fake_server_encrypted_handshake() -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    // ChangeCipherSpec (required for TLS 1.3 middlebox compatibility)
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    // Fake encrypted handshake records (appear as Application Data to DPI).
    // Randomize sizes to avoid a fixed statistical fingerprint.
    let r1_len = 1300 + (rand::random::<u16>() % 400) as usize;
    let r2_len = 1000 + (rand::random::<u16>() % 400) as usize;
    let fake_r1: Vec<u8> = (0..r1_len).map(|_| rand::random::<u8>()).collect();
    let fake_r2: Vec<u8> = (0..r2_len).map(|_| rand::random::<u8>()).collect();
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(r1_len as u16).to_be_bytes());
    out.extend_from_slice(&fake_r1);
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(r2_len as u16).to_be_bytes());
    out.extend_from_slice(&fake_r2);
    out
}

fn build_fake_client_finished() -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    // Client ChangeCipherSpec
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    // Client Finished (encrypted, appears as Application Data)
    let finished_len = 36 + (rand::random::<u8>() % 20) as usize;
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(finished_len as u16).to_be_bytes());
    let fake_finished: Vec<u8> = (0..finished_len).map(|_| rand::random::<u8>()).collect();
    out.extend_from_slice(&fake_finished);
    out
}

// --- Handshake logic ---

async fn drain_tls_records(stream: &mut TcpStream, count: usize) -> Result<(), TunnelError> {
    let mut hdr = [0u8; 5];
    for _ in 0..count {
        stream.read_exact(&mut hdr).await?;
        let record_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if record_len > 16384 {
            return Err(TunnelError::InternalError(
                "fakehttp: TLS record too large during handshake drain".to_string(),
            ));
        }
        // CCS records have content_type 0x14 and are only 1 byte payload
        // but we still read via the length field for uniformity
        let mut body = vec![0u8; record_len];
        stream.read_exact(&mut body).await?;
    }
    Ok(())
}

enum HandshakeResult {
    Plain,
    TlsWrapped,
}

async fn perform_client_handshake(
    stream: &mut TcpStream,
    payload: &FakeHttpPayload,
) -> Result<HandshakeResult, TunnelError> {
    let (data, ws_key) = payload.client_bytes();
    stream.write_all(&data).await?;

    match payload {
        FakeHttpPayload::Https { .. } => {
            drain_tls_records(stream, 4).await?;
            stream.write_all(&build_fake_client_finished()).await?;
            Ok(HandshakeResult::TlsWrapped)
        }
        FakeHttpPayload::Http { .. } => {
            let mut resp_buf = Vec::with_capacity(512);
            let mut tmp = [0u8; 512];
            loop {
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(TunnelError::InternalError(
                        "fakehttp handshake: server closed connection".to_string(),
                    ));
                }
                resp_buf.extend_from_slice(&tmp[..n]);
                if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if resp_buf.len() > 4096 {
                    return Err(TunnelError::InternalError(
                        "fakehttp handshake: response too large".to_string(),
                    ));
                }
            }
            if let Some(key) = ws_key {
                let expected_accept = compute_ws_accept(&key);
                let resp_str = String::from_utf8_lossy(&resp_buf);
                if !resp_str.contains(&expected_accept) {
                    tracing::warn!("fakehttp: server Sec-WebSocket-Accept mismatch");
                }
            }
            Ok(HandshakeResult::Plain)
        }
    }
}

async fn perform_server_handshake(stream: &mut TcpStream) -> Result<HandshakeResult, TunnelError> {
    let mut peek_buf = [0u8; 4];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Err(TunnelError::InternalError(
            "fakehttp handshake: client closed connection".to_string(),
        ));
    }

    if (n >= 3 && &peek_buf[..3] == b"GET") || (n >= 4 && &peek_buf[..4] == b"POST") {
        server_handle_http(stream).await?;
        Ok(HandshakeResult::Plain)
    } else if n >= 2 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03 {
        server_handle_tls(stream).await?;
        Ok(HandshakeResult::TlsWrapped)
    } else {
        Err(TunnelError::InternalError(
            "fakehttp: unrecognized protocol (expected HTTP or TLS)".to_string(),
        ))
    }
}

async fn server_handle_http(stream: &mut TcpStream) -> Result<(), TunnelError> {
    let mut buf = Vec::with_capacity(1024);
    let mut search_from: usize = 0;
    loop {
        let mut tmp = [0u8; 1024];
        let nr = stream.read(&mut tmp).await?;
        if nr == 0 {
            return Err(TunnelError::InternalError(
                "fakehttp: incomplete HTTP request".to_string(),
            ));
        }
        buf.extend_from_slice(&tmp[..nr]);
        let start = search_from.saturating_sub(3);
        if buf[start..].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        search_from = buf.len();
        if buf.len() > 8192 {
            return Err(TunnelError::InternalError(
                "fakehttp: HTTP request too large".to_string(),
            ));
        }
    }
    let ws_accept = extract_ws_key(&buf)
        .map(|key| compute_ws_accept(key))
        .unwrap_or_default();
    stream.write_all(&build_http_response(&ws_accept)).await?;
    Ok(())
}

fn extract_ws_key(headers: &[u8]) -> Option<&str> {
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

async fn server_handle_tls(stream: &mut TcpStream) -> Result<(), TunnelError> {
    // Read 5-byte TLS record header to get payload length
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > 16384 {
        return Err(TunnelError::InternalError(
            "fakehttp: TLS record too large".to_string(),
        ));
    }
    // Read the full record body to extract session_id
    let mut record_body = vec![0u8; record_len];
    stream.read_exact(&mut record_body).await?;

    // Parse session_id from ClientHello:
    // handshake_type(1) + length(3) + version(2) + random(32) + session_id_len(1) = offset 39
    let session_id = if record_body.len() > 39 {
        let sid_len = record_body[38] as usize;
        if record_body.len() >= 39 + sid_len {
            Some(&record_body[39..39 + sid_len])
        } else {
            None
        }
    } else {
        None
    };

    // Send ServerHello + fake encrypted handshake (CCS + encrypted records)
    let server_hello = build_tls_server_hello(session_id);
    let fake_hs = build_fake_server_encrypted_handshake();
    let mut combined = Vec::with_capacity(server_hello.len() + fake_hs.len());
    combined.extend_from_slice(&server_hello);
    combined.extend_from_slice(&fake_hs);
    stream.write_all(&combined).await?;

    // Read client's CCS + fake Finished (2 TLS records, variable size)
    drain_tls_records(stream, 2).await?;

    Ok(())
}


// --- Shared TCP connection helper ---

async fn tcp_connect(
    addr: SocketAddr,
    socket_mark: Option<u32>,
) -> Result<TcpStream, TunnelError> {
    if socket_mark.is_some() {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_socket_mark(&socket2::SockRef::from(&socket), socket_mark)?;
        Ok(socket.connect(addr).await?)
    } else {
        Ok(TcpStream::connect(addr).await?)
    }
}

fn build_tunnel_info(stream: &TcpStream, remote_url: &url::Url) -> Result<TunnelInfo, TunnelError> {
    Ok(TunnelInfo {
        tunnel_type: "fakehttp".to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "fakehttp").into(),
        ),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "fakehttp").into(),
        ),
    })
}

// --- Listener ---

#[derive(Debug)]
pub struct FakeHttpTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
    #[allow(dead_code)]
    payloads: Vec<FakeHttpPayload>,
}

impl FakeHttpTunnelListener {
    pub fn new(addr: url::Url, hosts: Vec<String>) -> Self {
        let payloads = parse_payloads(hosts);
        if payloads.is_empty() {
            tracing::warn!("fakehttp listener created with no valid payloads; will still accept connections");
        }
        FakeHttpTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
            payloads,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn do_accept(&self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let listener = self.listener.as_ref().unwrap();
        let (mut stream, _) = listener.accept().await?;

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(?e, "fakehttp: set_nodelay fail in accept");
        }

        let hs_result = timeout(HANDSHAKE_TIMEOUT, perform_server_handshake(&mut stream))
            .await
            .map_err(|_| {
                TunnelError::InternalError("fakehttp handshake timed out".to_string())
            })??;

        let local_url = self.local_url();
        let info = TunnelInfo {
            tunnel_type: "fakehttp".to_owned(),
            local_addr: Some(local_url.into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(
                    &stream.peer_addr()?.to_string(),
                    "fakehttp",
                )
                .into(),
            ),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(
                    &stream.peer_addr()?.to_string(),
                    "fakehttp",
                )
                .into(),
            ),
        };

        let (r, w) = stream.into_split();
        match hs_result {
            HandshakeResult::TlsWrapped => Ok(Box::new(TunnelWrapper::new(
                FramedReader::new(TlsRecordReader::new(r), TCP_MTU_BYTES),
                FramedWriter::new(TlsRecordWriter::new(w)),
                Some(info),
            ))),
            HandshakeResult::Plain => Ok(Box::new(TunnelWrapper::new(
                FramedReader::new(WsFrameReader::new(r), TCP_MTU_BYTES),
                FramedWriter::new(WsFrameWriter::new(w, false)),
                Some(info),
            ))),
        }
    }
}

#[async_trait]
impl TunnelListener for FakeHttpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        self.listener = None;
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let listener = bind::<TcpListener>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;
        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        self.listener = Some(listener);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        loop {
            match self.do_accept().await {
                Ok(ret) => return Ok(ret),
                Err(e) => {
                    let is_io_retryable = if let TunnelError::IOError(io) = &e {
                        matches!(
                            io.kind(),
                            std::io::ErrorKind::NotConnected
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                        )
                    } else {
                        false
                    };
                    let should_retry =
                        is_io_retryable || matches!(&e, TunnelError::InternalError(_));
                    if should_retry {
                        tracing::warn!(?e, "fakehttp accept: retryable error");
                        continue;
                    }
                    tracing::warn!(?e, "fakehttp accept fail");
                    return Err(e);
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

// --- Connector ---

#[derive(Debug)]
pub struct FakeHttpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
    payloads: Vec<FakeHttpPayload>,
    counter: AtomicUsize,
}

impl FakeHttpTunnelConnector {
    pub fn new(addr: url::Url, hosts: Vec<String>) -> Self {
        let payloads = parse_payloads(hosts);
        FakeHttpTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
            payloads,
            counter: AtomicUsize::new(0),
        }
    }

    fn next_payload(&self) -> &FakeHttpPayload {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.payloads.len();
        &self.payloads[idx]
    }
}

#[async_trait]
impl super::TunnelConnector for FakeHttpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        if self.payloads.is_empty() {
            return Err(TunnelError::InternalError(
                "no valid fakehttp payload configured".to_string(),
            ));
        }

        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };

        tracing::info!(url = ?self.addr, ?addr, "fakehttp connect start");

        let mut stream = if self.bind_addrs.is_empty() {
            tcp_connect(addr, self.socket_mark).await?
        } else {
            let futures = FuturesUnordered::new();
            for bind_addr in &self.bind_addrs {
                match bind::<TcpSocket>()
                    .addr(*bind_addr)
                    .only_v6(true)
                    .maybe_socket_mark(self.socket_mark)
                    .call()
                {
                    Ok(socket) => futures.push(socket.connect(addr)),
                    Err(e) => {
                        tracing::error!(?bind_addr, ?addr, ?e, "fakehttp bind fail");
                    }
                }
            }
            wait_for_connect_futures(futures).await?
        };

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(?e, "fakehttp: set_nodelay fail");
        }

        let payload = self.next_payload();
        let hs_result = timeout(HANDSHAKE_TIMEOUT, perform_client_handshake(&mut stream, payload))
            .await
            .map_err(|_| {
                TunnelError::InternalError(
                    "fakehttp handshake timed out, remote may not support fakehttp".to_string(),
                )
            })??;

        tracing::info!(url = ?self.addr, ?addr, "fakehttp connect success");

        let info = build_tunnel_info(&stream, &self.addr)?;
        let (r, w) = stream.into_split();
        match hs_result {
            HandshakeResult::TlsWrapped => Ok(Box::new(TunnelWrapper::new(
                FramedReader::new(TlsRecordReader::new(r), TCP_MTU_BYTES),
                FramedWriter::new(TlsRecordWriter::new(w)),
                Some(info),
            ))),
            HandshakeResult::Plain => Ok(Box::new(TunnelWrapper::new(
                FramedReader::new(WsFrameReader::new(r), TCP_MTU_BYTES),
                FramedWriter::new(WsFrameWriter::new(w, true)),
                Some(info),
            ))),
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{
        TunnelConnector,
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };

    use super::*;

    fn http_hosts() -> Vec<String> {
        vec!["http://www.example.com".to_string()]
    }

    fn https_hosts() -> Vec<String> {
        vec!["https://www.example.com".to_string()]
    }

    #[tokio::test]
    async fn fakehttp_http_pingpong() {
        let listener =
            FakeHttpTunnelListener::new("fakehttp://0.0.0.0:41011".parse().unwrap(), http_hosts());
        let connector = FakeHttpTunnelConnector::new(
            "fakehttp://127.0.0.1:41011".parse().unwrap(),
            http_hosts(),
        );
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn fakehttp_https_pingpong() {
        let listener = FakeHttpTunnelListener::new(
            "fakehttp://0.0.0.0:41012".parse().unwrap(),
            https_hosts(),
        );
        let connector = FakeHttpTunnelConnector::new(
            "fakehttp://127.0.0.1:41012".parse().unwrap(),
            https_hosts(),
        );
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn fakehttp_http_bench() {
        let listener =
            FakeHttpTunnelListener::new("fakehttp://0.0.0.0:41013".parse().unwrap(), http_hosts());
        let connector = FakeHttpTunnelConnector::new(
            "fakehttp://127.0.0.1:41013".parse().unwrap(),
            http_hosts(),
        );
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn fakehttp_ipv6_pingpong() {
        let listener =
            FakeHttpTunnelListener::new("fakehttp://[::1]:41014".parse().unwrap(), http_hosts());
        let connector = FakeHttpTunnelConnector::new(
            "fakehttp://[::1]:41014".parse().unwrap(),
            http_hosts(),
        );
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn fakehttp_no_payload_connector_fails() {
        let mut connector = FakeHttpTunnelConnector::new(
            "fakehttp://127.0.0.1:41015".parse().unwrap(),
            vec!["invalid_entry".to_string()],
        );
        let result = connector.connect().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no valid fakehttp payload"));
    }

    // --- DPI Detection Tests ---

    const GREASE_VALUES: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];

    fn is_grease(val: u16) -> bool {
        GREASE_VALUES.contains(&val)
    }

    fn parse_tls_record(data: &[u8]) -> Option<(u8, [u8; 2], &[u8])> {
        if data.len() < 5 {
            return None;
        }
        let content_type = data[0];
        let version = [data[1], data[2]];
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + length {
            return None;
        }
        Some((content_type, version, &data[5..5 + length]))
    }

    fn parse_handshake(payload: &[u8]) -> Option<(u8, &[u8])> {
        if payload.len() < 4 {
            return None;
        }
        let hs_type = payload[0];
        let length =
            ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
        if payload.len() < 4 + length {
            return None;
        }
        Some((hs_type, &payload[4..4 + length]))
    }

    fn find_extension(extensions_data: &[u8], target_type: u16) -> Option<&[u8]> {
        let mut offset = 0;
        while offset + 4 <= extensions_data.len() {
            let ext_type =
                u16::from_be_bytes([extensions_data[offset], extensions_data[offset + 1]]);
            let ext_len = u16::from_be_bytes([
                extensions_data[offset + 2],
                extensions_data[offset + 3],
            ]) as usize;
            if offset + 4 + ext_len > extensions_data.len() {
                break;
            }
            if ext_type == target_type {
                return Some(&extensions_data[offset + 4..offset + 4 + ext_len]);
            }
            offset += 4 + ext_len;
        }
        None
    }

    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    struct ClientHelloFields<'a> {
        version: [u8; 2],
        random: &'a [u8],
        session_id: &'a [u8],
        cipher_suites: Vec<u16>,
        extensions_raw: &'a [u8],
    }

    fn parse_client_hello(body: &[u8]) -> Option<ClientHelloFields<'_>> {
        if body.len() < 38 {
            return None;
        }
        let version = [body[0], body[1]];
        let random = &body[2..34];
        let sid_len = body[34] as usize;
        if body.len() < 35 + sid_len {
            return None;
        }
        let session_id = &body[35..35 + sid_len];
        let mut offset = 35 + sid_len;

        // cipher suites
        if offset + 2 > body.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        if offset + cs_len > body.len() {
            return None;
        }
        let mut cipher_suites = Vec::new();
        let cs_data = &body[offset..offset + cs_len];
        for chunk in cs_data.chunks_exact(2) {
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        offset += cs_len;

        // compression
        if offset + 1 > body.len() {
            return None;
        }
        let comp_len = body[offset] as usize;
        offset += 1 + comp_len;

        // extensions
        if offset + 2 > body.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        let extensions_raw = if offset + ext_len <= body.len() {
            &body[offset..offset + ext_len]
        } else {
            &body[offset..]
        };

        Some(ClientHelloFields {
            version,
            random,
            session_id,
            cipher_suites,
            extensions_raw,
        })
    }

    #[test]
    fn test_dpi_tls_record_format() {
        let data = build_tls_client_hello("www.google.com");
        let (ct, ver, payload) = parse_tls_record(&data).expect("valid TLS record");
        assert_eq!(ct, 0x16, "content_type should be Handshake");
        assert_eq!(ver, [0x03, 0x01], "record version should be TLS 1.0");
        let (hs_type, _body) = parse_handshake(payload).expect("valid handshake");
        assert_eq!(hs_type, 0x01, "handshake type should be ClientHello");

        let server_data = build_tls_server_hello(Some(&[0xAA; 32]));
        let (ct, ver, payload) = parse_tls_record(&server_data).expect("valid ServerHello record");
        assert_eq!(ct, 0x16);
        assert_eq!(ver, [0x03, 0x03], "ServerHello record version should be TLS 1.2");
        let (hs_type, _) = parse_handshake(payload).expect("valid handshake");
        assert_eq!(hs_type, 0x02, "handshake type should be ServerHello");
    }

    #[test]
    fn test_dpi_tls_client_hello_fields() {
        let data = build_tls_client_hello("example.com");
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();
        let ch = parse_client_hello(body).expect("valid ClientHello");

        assert_eq!(ch.version, [0x03, 0x03], "protocol version TLS 1.2");
        assert_eq!(ch.random.len(), 32);
        assert!(ch.random.iter().any(|&b| b != 0), "random should not be all zeros");
        assert_eq!(ch.session_id.len(), 32);
        assert!(ch.session_id.iter().any(|&b| b != 0), "session_id should not be all zeros");
        assert!(
            ch.cipher_suites.iter().any(|&cs| is_grease(cs)),
            "should contain GREASE cipher suite"
        );
        assert!(
            ch.cipher_suites.contains(&0x1301),
            "should contain TLS_AES_128_GCM"
        );
        assert!(
            ch.cipher_suites.contains(&0x1302),
            "should contain TLS_AES_256_GCM"
        );
        assert!(
            ch.cipher_suites.contains(&0x1303),
            "should contain TLS_CHACHA20"
        );
    }

    #[test]
    fn test_dpi_tls_extensions_presence() {
        let host = "www.google.com";
        let data = build_tls_client_hello(host);
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();
        let ch = parse_client_hello(body).unwrap();
        let ext = ch.extensions_raw;

        // SNI
        let sni = find_extension(ext, 0x0000).expect("should have SNI extension");
        let sni_str = std::str::from_utf8(&sni[5..]).unwrap_or("");
        assert_eq!(sni_str, host, "SNI hostname should match");

        // key_share
        assert!(find_extension(ext, 0x0033).is_some(), "should have key_share");

        // supported_versions
        assert!(find_extension(ext, 0x002b).is_some(), "should have supported_versions");

        // ALPN
        let alpn = find_extension(ext, 0x0010).expect("should have ALPN");
        let alpn_str = String::from_utf8_lossy(alpn);
        assert!(alpn_str.contains("h2"), "ALPN should contain h2");

        // session_ticket
        assert!(find_extension(ext, 0x0023).is_some(), "should have session_ticket");

        // status_request
        assert!(find_extension(ext, 0x0005).is_some(), "should have status_request");

        // GREASE extension
        let mut has_grease_ext = false;
        let mut offset = 0;
        while offset + 4 <= ext.len() {
            let ext_type = u16::from_be_bytes([ext[offset], ext[offset + 1]]);
            let ext_len =
                u16::from_be_bytes([ext[offset + 2], ext[offset + 3]]) as usize;
            if is_grease(ext_type) {
                has_grease_ext = true;
                break;
            }
            offset += 4 + ext_len;
        }
        assert!(has_grease_ext, "should have GREASE extension");
    }

    #[test]
    fn test_dpi_tls_hello_length() {
        let data = build_tls_client_hello("www.example.com");
        assert!(
            data.len() >= 517,
            "ClientHello record should be >= 517 bytes (got {})",
            data.len()
        );
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();
        assert!(
            body.len() >= 512,
            "ClientHello body should be >= 512 bytes (got {})",
            body.len()
        );
    }

    #[test]
    fn test_dpi_tls_server_hello_compliance() {
        let client_sid: [u8; 32] = rand::random();
        let server_data = build_tls_server_hello(Some(&client_sid));
        let (_, _, payload) = parse_tls_record(&server_data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();

        // Parse ServerHello: version(2) + random(32) + sid_len(1) + sid + cipher(2) + comp(1) + ext
        assert!(body.len() > 70, "ServerHello body too short");
        let sid_len = body[34] as usize;
        assert_eq!(sid_len, 32);
        let server_sid = &body[35..35 + sid_len];
        assert_eq!(server_sid, &client_sid, "ServerHello should echo client session_id");

        // Check extensions exist
        // ServerHello body: version(2) + random(32) + sid_len(1) + sid(32) + cipher(2) + comp(1)
        let offset = 2 + 32 + 1 + sid_len + 2 + 1;
        assert!(body.len() > offset + 2, "ServerHello should have extensions");
        let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        assert!(ext_len > 0, "ServerHello extensions should not be empty");

        let ext_data = &body[offset + 2..offset + 2 + ext_len];
        assert!(
            find_extension(ext_data, 0x002b).is_some(),
            "should have supported_versions extension"
        );
        assert!(
            find_extension(ext_data, 0x0033).is_some(),
            "should have key_share extension"
        );
    }

    #[test]
    fn test_dpi_tls_randomness() {
        let data1 = build_tls_client_hello("example.com");
        let data2 = build_tls_client_hello("example.com");

        let (_, _, p1) = parse_tls_record(&data1).unwrap();
        let (_, _, p2) = parse_tls_record(&data2).unwrap();
        let (_, b1) = parse_handshake(p1).unwrap();
        let (_, b2) = parse_handshake(p2).unwrap();

        let random1 = &b1[2..34];
        let random2 = &b2[2..34];
        assert_ne!(random1, random2, "random should differ between calls");

        let sid1 = &b1[35..67];
        let sid2 = &b2[35..67];
        assert_ne!(sid1, sid2, "session_id should differ between calls");
    }

    #[test]
    fn test_dpi_tls_entropy() {
        let data = build_tls_client_hello("www.google.com");
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();

        let random = &body[2..34];
        let entropy = shannon_entropy(random);
        assert!(
            entropy > 3.5,
            "random field entropy should be reasonable (got {:.2})",
            entropy
        );

        // Test with simulated encrypted payload
        let encrypted: Vec<u8> = (0..1400).map(|_| rand::random::<u8>()).collect();
        let entropy = shannon_entropy(&encrypted);
        assert!(
            entropy > 7.8,
            "AES-like random data should have high entropy (got {:.2})",
            entropy
        );
    }

    #[test]
    fn test_dpi_http_request_headers() {
        let host = "ws.example.com";
        let (req, ws_key) = build_http_request(host);
        let req_str = String::from_utf8_lossy(&req);

        assert!(req_str.starts_with("GET / HTTP/1.1\r\n"), "should start with GET");
        assert!(req_str.ends_with("\r\n\r\n"), "should end with double CRLF");
        assert!(req_str.contains(&format!("Host: {}", host)), "should have Host header");
        assert!(req_str.contains("Connection: Upgrade"), "should have Connection: Upgrade");
        assert!(req_str.contains("Upgrade: websocket"), "should have Upgrade: websocket");
        assert!(
            req_str.contains("Sec-WebSocket-Version: 13"),
            "should have WS version"
        );
        assert!(req_str.contains("Sec-WebSocket-Key: "), "should have WS key");
        assert!(
            req_str.contains(&format!("Origin: http://{}", host)),
            "should have Origin"
        );
        assert!(
            req_str.contains("Sec-WebSocket-Extensions: permessage-deflate"),
            "should have WS extensions"
        );
        assert!(req_str.contains("Chrome/"), "should have Chrome User-Agent");
        assert!(req_str.contains("Pragma: no-cache"), "should have Pragma");
        assert!(req_str.contains("Cache-Control: no-cache"), "should have Cache-Control");

        // Validate returned key matches the one in the request
        assert_eq!(ws_key.len(), 24, "WS key should be 24 chars base64");
        assert!(req_str.contains(&ws_key), "returned key should match request");
    }

    #[test]
    fn test_dpi_http_response_format() {
        let ws_accept = compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==");
        let resp = build_http_response(&ws_accept);
        let resp_str = String::from_utf8_lossy(&resp);

        assert!(
            resp_str.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "should be 101 response"
        );
        assert!(resp_str.ends_with("\r\n\r\n"), "should end with double CRLF");
        assert!(resp_str.contains("Connection: Upgrade"), "should have Connection: Upgrade");
        assert!(resp_str.contains("Upgrade: websocket"), "should have Upgrade: websocket");
        assert!(
            resp_str.contains(&format!("Sec-WebSocket-Accept: {}", ws_accept)),
            "should have computed WS Accept"
        );
        assert!(resp_str.contains("Date:"), "should have Date header");
    }

    #[test]
    fn test_ws_accept_roundtrip() {
        let ws_key: [u8; 16] = rand::random();
        let key_b64 = BASE64_STANDARD.encode(ws_key);
        let accept = compute_ws_accept(&key_b64);
        assert!(!accept.is_empty());
        assert_ne!(accept, key_b64);
        // Verify deterministic
        assert_eq!(accept, compute_ws_accept(&key_b64));
    }

    #[test]
    fn test_dpi_tls_empty_host() {
        let data = build_tls_client_hello("");
        let (ct, _, _) = parse_tls_record(&data).expect("should produce valid record");
        assert_eq!(ct, 0x16);
    }

    #[test]
    fn test_dpi_tls_long_host() {
        let long_host = "a".repeat(255);
        let data = build_tls_client_hello(&long_host);
        let (ct, _, payload) = parse_tls_record(&data).expect("should produce valid record");
        assert_eq!(ct, 0x16);
        assert!(payload.len() <= 16384, "should not exceed TLS max record");
    }
}
