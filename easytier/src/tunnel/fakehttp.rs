use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
const MAX_RAW_PAYLOAD_SIZE: usize = 2048;

// --- Payload types ---

#[derive(Debug, Clone)]
enum FakeHttpPayload {
    Http { host: String },
    Https { host: String },
    RawFile {
        wire_data: Vec<u8>, // pre-computed: 4-byte length prefix + file content
    },
}

impl FakeHttpPayload {
    fn client_bytes(&self) -> Vec<u8> {
        match self {
            Self::Http { host } => build_http_request(host),
            Self::Https { host } => build_tls_client_hello(host),
            Self::RawFile { wire_data } => wire_data.clone(),
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
            match std::fs::read(&entry) {
                Ok(mut data) => {
                    if data.len() > MAX_RAW_PAYLOAD_SIZE {
                        tracing::warn!(
                            path = %entry,
                            size = data.len(),
                            max = MAX_RAW_PAYLOAD_SIZE,
                            "fakehttp payload file truncated"
                        );
                        data.truncate(MAX_RAW_PAYLOAD_SIZE);
                    }
                    // Pre-compute wire format: 4-byte BE length + data
                    let mut wire_data = Vec::with_capacity(4 + data.len());
                    wire_data.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    wire_data.extend_from_slice(&data);
                    payloads.push(FakeHttpPayload::RawFile { wire_data });
                }
                Err(e) => {
                    tracing::warn!(path = %entry, error = %e, "fakehttp payload file not found, skipping");
                }
            }
        }
    }
    payloads
}

// --- Protocol builders ---

fn build_http_request(host: &str) -> Vec<u8> {
    // Use HTTP Upgrade mechanism (RFC 7230 §6.7) to legitimize the protocol switch.
    // After 101 response, DPI state machines expect non-HTTP binary framing.
    let ws_key: [u8; 16] = rand::random();
    let ws_key_b64 = base64_encode(&ws_key);
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         Accept: */*\r\n\
         Accept-Language: en-US,en;q=0.5\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {ws_key_b64}\r\n\
         \r\n"
    )
    .into_bytes()
}

fn build_http_response() -> Vec<u8> {
    let date_str = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    // 101 Switching Protocols legitimizes the binary data that follows.
    // DPI state machines treat this as a valid protocol upgrade.
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Date: {date_str}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
         Server: nginx/1.24.0\r\n\
         \r\n"
    )
    .into_bytes()
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Wrap a handshake body in TLS record + handshake headers.
/// `hs_type`: 0x01 = ClientHello, 0x02 = ServerHello
/// `record_version`: protocol version in the record layer header
fn wrap_tls_handshake(hs_type: u8, body: &[u8], record_version: [u8; 2]) -> Vec<u8> {
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

fn build_tls_client_hello(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();

    // Pick a random GREASE value for this connection (Chrome behavior)
    const GREASE_VALUES: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let grease_idx: u8 = rand::random::<u8>() % GREASE_VALUES.len() as u8;
    let grease = GREASE_VALUES[grease_idx as usize];
    let grease_bytes = grease.to_be_bytes();

    // Extensions (ordered like Chrome)
    let mut extensions = Vec::with_capacity(256);

    // GREASE extension (Chrome inserts one at the start)
    extensions.extend_from_slice(&grease_bytes); // type: GREASE
    extensions.extend_from_slice(&[0x00, 0x00]); // empty data

    // SNI (RFC 6066)
    let sni_name_len = host_bytes.len();
    let sni_list_len = 1 + 2 + sni_name_len;
    let sni_ext_data_len = 2 + sni_list_len;
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name
    extensions.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(sni_name_len as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    // extended_master_secret (0x0017)
    extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // renegotiation_info (0xff01)
    extensions.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // supported_groups (0x000a) with GREASE
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a]);
    extensions.extend_from_slice(&grease_bytes); // GREASE group
    extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1
    extensions.extend_from_slice(&[0x00, 0x18]); // secp384r1
    extensions.extend_from_slice(&[0x00, 0x19]); // secp521r1

    // ec_point_formats (0x000b)
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]); // uncompressed

    // signature_algorithms (0x000d) - realistic set
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x12, 0x00, 0x10]);
    extensions.extend_from_slice(&[0x04, 0x03]); // ecdsa_secp256r1_sha256
    extensions.extend_from_slice(&[0x08, 0x04]); // rsa_pss_rsae_sha256
    extensions.extend_from_slice(&[0x04, 0x01]); // rsa_pkcs1_sha256
    extensions.extend_from_slice(&[0x05, 0x03]); // ecdsa_secp384r1_sha384
    extensions.extend_from_slice(&[0x08, 0x05]); // rsa_pss_rsae_sha384
    extensions.extend_from_slice(&[0x05, 0x01]); // rsa_pkcs1_sha384
    extensions.extend_from_slice(&[0x08, 0x06]); // rsa_pss_rsae_sha512
    extensions.extend_from_slice(&[0x06, 0x01]); // rsa_pkcs1_sha512

    // ALPN (0x0010)
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

    // supported_versions (0x002b) - advertise TLS 1.3 + 1.2
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04]);
    extensions.extend_from_slice(&grease_bytes); // GREASE version
    extensions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 (we don't do 1.3 but advertising it is fine)

    // psk_key_exchange_modes (0x002d)
    extensions.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]); // psk_dhe_ke

    // ClientHello body
    let mut body = Vec::with_capacity(256 + extensions.len());
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    body.push(0x20); // session_id_len = 32
    let session_id: [u8; 32] = rand::random();
    body.extend_from_slice(&session_id);
    // Cipher suites with GREASE (Chrome-like ordering)
    body.extend_from_slice(&[0x00, 0x10]); // 16 bytes = 8 suites (including GREASE)
    body.extend_from_slice(&grease_bytes); // GREASE cipher
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
    body.extend_from_slice(&[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256
    body.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0xc0, 0x2c]); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    body.extend_from_slice(&[0xc0, 0x30]); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    // Compression
    body.extend_from_slice(&[0x01, 0x00]);
    // Extensions
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    wrap_tls_handshake(0x01, &body, [0x03, 0x01])
}

fn build_tls_server_hello() -> Vec<u8> {
    let mut body = Vec::with_capacity(70);
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    let random: [u8; 32] = rand::random();
    body.extend_from_slice(&random);
    body.push(0x20); // session_id_len = 32
    let session_id: [u8; 32] = rand::random();
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&[0xc0, 0x2b]); // cipher suite
    body.push(0x00); // compression: null

    // Record layer uses TLS 1.2
    wrap_tls_handshake(0x02, &body, [0x03, 0x03])
}

// --- Handshake logic ---

async fn perform_client_handshake(
    stream: &mut TcpStream,
    payload: &FakeHttpPayload,
) -> Result<(), TunnelError> {
    let data = payload.client_bytes();
    stream.write_all(&data).await?;

    // Read server response (we only need to confirm something came back)
    let mut resp_buf = [0u8; 512];
    let n = stream.read(&mut resp_buf).await?;
    if n == 0 {
        return Err(TunnelError::InternalError(
            "fakehttp handshake: server closed connection".to_string(),
        ));
    }
    Ok(())
}

async fn perform_server_handshake(stream: &mut TcpStream) -> Result<(), TunnelError> {
    let mut peek_buf = [0u8; 4];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Err(TunnelError::InternalError(
            "fakehttp handshake: client closed connection".to_string(),
        ));
    }

    if (n >= 3 && &peek_buf[..3] == b"GET") || (n >= 4 && &peek_buf[..4] == b"POST") {
        server_handle_http(stream).await
    } else if n >= 2 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03 {
        server_handle_tls(stream).await
    } else {
        server_handle_raw(stream).await
    }
}

async fn server_handle_http(stream: &mut TcpStream) -> Result<(), TunnelError> {
    // Read until \r\n\r\n (end of HTTP headers)
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
        // Only search the newly added region (with 3 bytes overlap for boundary)
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
    stream.write_all(&build_http_response()).await?;
    Ok(())
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
    // Drain the record body
    let mut remaining = record_len;
    let mut discard = [0u8; 4096];
    while remaining > 0 {
        let to_read = remaining.min(discard.len());
        stream.read_exact(&mut discard[..to_read]).await?;
        remaining -= to_read;
    }
    stream.write_all(&build_tls_server_hello()).await?;
    Ok(())
}

async fn server_handle_raw(stream: &mut TcpStream) -> Result<(), TunnelError> {
    // 4-byte BE length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    if payload_len > MAX_RAW_PAYLOAD_SIZE {
        return Err(TunnelError::InternalError(
            "fakehttp: raw payload too large".to_string(),
        ));
    }
    // Drain payload
    let mut remaining = payload_len;
    let mut discard = [0u8; 2048];
    while remaining > 0 {
        let to_read = remaining.min(discard.len());
        stream.read_exact(&mut discard[..to_read]).await?;
        remaining -= to_read;
    }
    stream
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
        .await?;
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

        timeout(HANDSHAKE_TIMEOUT, perform_server_handshake(&mut stream))
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
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, TCP_MTU_BYTES),
            FramedWriter::new(w),
            Some(info),
        )))
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
        timeout(HANDSHAKE_TIMEOUT, perform_client_handshake(&mut stream, payload))
            .await
            .map_err(|_| {
                TunnelError::InternalError(
                    "fakehttp handshake timed out, remote may not support fakehttp".to_string(),
                )
            })??;

        tracing::info!(url = ?self.addr, ?addr, "fakehttp connect success");

        let info = build_tunnel_info(&stream, &self.addr)?;
        let (r, w) = stream.into_split();
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, TCP_MTU_BYTES),
            FramedWriter::new(w),
            Some(info),
        )))
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
            vec!["/nonexistent/file.bin".to_string()],
        );
        let result = connector.connect().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no valid fakehttp payload"));
    }

    #[tokio::test]
    async fn fakehttp_raw_file_pingpong() {
        let tmp_dir = std::env::temp_dir();
        let tmp_file = tmp_dir.join("fakehttp_test_payload.bin");
        std::fs::write(&tmp_file, b"FAKE_PAYLOAD_DATA_FOR_TESTING_1234567890").unwrap();

        let hosts = vec![tmp_file.to_string_lossy().to_string()];
        let listener =
            FakeHttpTunnelListener::new("fakehttp://0.0.0.0:41016".parse().unwrap(), hosts.clone());
        let connector = FakeHttpTunnelConnector::new(
            "fakehttp://127.0.0.1:41016".parse().unwrap(),
            hosts,
        );
        _tunnel_pingpong(listener, connector).await;

        std::fs::remove_file(&tmp_file).ok();
    }
}
