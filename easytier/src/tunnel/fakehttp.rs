use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use easytier_core::{
    socket::tcp::VirtualTcpSocket,
    tunnel::{Tunnel, TunnelError, framed::{FramedReader, FramedWriter}, wrapper::TunnelWrapper},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::disguise_protocol::{
    self, build_fake_client_finished, build_fake_server_encrypted_handshake, build_http_request,
    build_http_response, build_tls_client_hello, build_tls_server_hello, compute_ws_accept,
    extract_ws_key,
};
use crate::proto::common::TunnelInfo;

const TCP_MTU_BYTES: usize = 2000;
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

// --- Payload types ---

#[derive(Debug, Clone)]
pub(crate) enum FakeHttpPayload {
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

pub(crate) fn parse_payloads(hosts: Vec<String>) -> Vec<FakeHttpPayload> {
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

// --- TLS Application Data record IO adapters ---

const TLS_RECORD_HEADER_SIZE: usize = disguise_protocol::TLS_RECORD_HEADER_SIZE;
const TLS_MAX_PLAINTEXT: usize = disguise_protocol::TLS_MAX_PLAINTEXT;

struct TlsRecordWriter<W> {
    inner: W,
    send_buf: Vec<u8>,
    send_pos: usize,
    payload_len: usize,
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
            let n = me.payload_len;
            me.send_buf.clear();
            me.send_pos = 0;
            me.payload_len = 0;
            return Poll::Ready(Ok(n));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = buf.len().min(TLS_MAX_PLAINTEXT);
        me.send_buf.reserve(TLS_RECORD_HEADER_SIZE + chunk_len);
        me.send_buf
            .extend_from_slice(&[0x17, 0x03, 0x03, (chunk_len >> 8) as u8, chunk_len as u8]);
        me.send_buf.extend_from_slice(&buf[..chunk_len]);
        me.send_pos = 0;
        me.payload_len = chunk_len;

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

        let mut raw = [0u8; 4096];
        let mut raw_buf = ReadBuf::new(&mut raw);
        match Pin::new(&mut me.inner).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(())) => {
                let n = raw_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }

                let data = &raw[..n];
                let mut i = 0;

                if me.hdr_len > 0 {
                    let need = TLS_RECORD_HEADER_SIZE - me.hdr_len;
                    let avail = data.len().min(need);
                    me.hdr_buf[me.hdr_len..me.hdr_len + avail]
                        .copy_from_slice(&data[..avail]);
                    me.hdr_len += avail;
                    i = avail;

                    if me.hdr_len < TLS_RECORD_HEADER_SIZE {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }

                    if me.hdr_buf[0] == 0x17 && me.hdr_buf[1] == 0x03 {
                        me.remaining_in_record =
                            u16::from_be_bytes([me.hdr_buf[3], me.hdr_buf[4]]) as usize;
                    } else {
                        me.residual
                            .extend_from_slice(&me.hdr_buf[..TLS_RECORD_HEADER_SIZE]);
                    }
                    me.hdr_len = 0;
                }

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
                        let partial = data.len() - i;
                        me.hdr_buf[..partial].copy_from_slice(&data[i..]);
                        me.hdr_len = partial;
                        i = data.len();
                    }
                }

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

struct WsFrameWriter<W> {
    inner: W,
    is_client: bool,
    send_buf: Vec<u8>,
    send_offset: usize,
    pending_payload_len: usize,
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
                    while me.hdr_read < me.hdr_len {
                        let mut tmp = ReadBuf::new(&mut me.hdr_buf[me.hdr_read..me.hdr_len]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp.filled().len();
                                if n == 0 {
                                    return if me.hdr_read == 0 {
                                        Poll::Ready(Ok(()))
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
                        }
                    }

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

                    let opcode = me.hdr_buf[0] & 0x0F;
                    if opcode >= 0x08 {
                        if me.remaining_payload == 0 {
                            me.reset_for_next_frame();
                            continue;
                        }
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
                        me.reset_for_next_frame();
                        continue;
                    }

                    me.state = WsReadState::ReadingPayload;
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
                                buf.set_filled(before + n);
                                return Poll::Ready(Ok(()));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
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

// --- Handshake logic ---

async fn drain_tls_records<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    count: usize,
) -> Result<(), TunnelError> {
    let mut hdr = [0u8; 5];
    for _ in 0..count {
        stream.read_exact(&mut hdr).await?;
        let record_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if record_len > 16384 {
            return Err(TunnelError::InternalError(
                "fakehttp: TLS record too large during handshake drain".to_string(),
            ));
        }
        let mut body = vec![0u8; record_len];
        stream.read_exact(&mut body).await?;
    }
    Ok(())
}

enum HandshakeResult {
    Plain,
    TlsWrapped,
}

async fn perform_client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &FakeHttpPayload,
) -> Result<HandshakeResult, TunnelError> {
    let (data, ws_key) = payload.client_bytes();
    stream.write_all(&data).await?;
    stream.flush().await?;

    match payload {
        FakeHttpPayload::Https { .. } => {
            drain_tls_records(stream, 4).await?;
            stream.write_all(&build_fake_client_finished()).await?;
            stream.flush().await?;
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

async fn server_handle_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    first_bytes: &[u8],
) -> Result<(), TunnelError> {
    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(first_bytes);
    let mut search_from: usize = 0;
    if buf[search_from..].windows(4).any(|w| w == b"\r\n\r\n") {
        let ws_accept = extract_ws_key(&buf)
            .map(|key| compute_ws_accept(key))
            .unwrap_or_default();
        stream.write_all(&build_http_response(&ws_accept)).await?;
        stream.flush().await?;
        return Ok(());
    }
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
    stream.flush().await?;
    Ok(())
}

async fn server_handle_tls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    first_bytes: &[u8],
) -> Result<(), TunnelError> {
    // We already have the first bytes of the TLS record header.
    // Read the remaining header byte(s) to complete the 5-byte TLS record header.
    let mut header = [0u8; 5];
    header[..first_bytes.len()].copy_from_slice(first_bytes);
    if first_bytes.len() < 5 {
        stream
            .read_exact(&mut header[first_bytes.len()..])
            .await?;
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > 16384 {
        return Err(TunnelError::InternalError(
            "fakehttp: TLS record too large".to_string(),
        ));
    }
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

    let server_hello = build_tls_server_hello(session_id);
    let fake_hs = build_fake_server_encrypted_handshake();
    let mut combined = Vec::with_capacity(server_hello.len() + fake_hs.len());
    combined.extend_from_slice(&server_hello);
    combined.extend_from_slice(&fake_hs);
    stream.write_all(&combined).await?;
    stream.flush().await?;

    drain_tls_records(stream, 2).await?;

    Ok(())
}

// --- Public upgrade functions ---

pub(crate) async fn upgrade_accepted<S: VirtualTcpSocket>(
    mut socket: S,
    local_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let peer_addr = socket.peer_addr()?;

    // Read first 4 bytes to detect protocol (replaces peek)
    let mut first_bytes = [0u8; 4];
    socket.read_exact(&mut first_bytes).await?;

    let hs_result = if (first_bytes[..3] == *b"GET") || (first_bytes[..4] == *b"POST") {
        server_handle_http(&mut socket, &first_bytes).await?;
        HandshakeResult::Plain
    } else if first_bytes[0] == 0x16 && first_bytes[1] == 0x03 {
        server_handle_tls(&mut socket, &first_bytes).await?;
        HandshakeResult::TlsWrapped
    } else {
        return Err(TunnelError::InternalError(
            "fakehttp: unrecognized protocol (expected HTTP or TLS)".to_string(),
        ));
    };

    let info = TunnelInfo {
        tunnel_type: "fakehttp".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(
            super::build_url_from_socket_addr(&peer_addr.to_string(), "fakehttp").into(),
        ),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(&peer_addr.to_string(), "fakehttp").into(),
        ),
    };

    let (r, w) = socket.into_split();
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

pub(crate) async fn upgrade_connected<S: VirtualTcpSocket>(
    mut socket: S,
    requested_url: url::Url,
    payloads: &[FakeHttpPayload],
    counter: &AtomicUsize,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    if payloads.is_empty() {
        return Err(TunnelError::InternalError(
            "no valid fakehttp payload configured".to_string(),
        ));
    }

    let local_addr = socket.local_addr()?;
    let peer_addr = socket.peer_addr()?;

    let idx = counter.fetch_add(1, Ordering::Relaxed) % payloads.len();
    let payload = &payloads[idx];

    let hs_result = perform_client_handshake(&mut socket, payload).await?;

    let info = TunnelInfo {
        tunnel_type: "fakehttp".to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&local_addr.to_string(), "fakehttp").into(),
        ),
        remote_addr: Some(requested_url.into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(&peer_addr.to_string(), "fakehttp").into(),
        ),
    };

    let (r, w) = socket.into_split();
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::{BASE64_STANDARD, Engine as _};
    use tokio::net::{TcpListener, TcpStream};

    use crate::socket::tcp::RuntimeTcpSocket;

    fn http_hosts() -> Vec<String> {
        vec!["http://www.example.com".to_string()]
    }

    fn https_hosts() -> Vec<String> {
        vec!["https://www.example.com".to_string()]
    }

    async fn test_pingpong(hosts: Vec<String>, port: u16) {
        let payloads = parse_payloads(hosts);
        let counter = AtomicUsize::new(0);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let local_url: url::Url = format!("fakehttp://127.0.0.1:{}", listener.local_addr().unwrap().port())
            .parse()
            .unwrap();

        let server_url = local_url.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = RuntimeTcpSocket::new(stream);
            upgrade_accepted(socket, server_url).await.unwrap()
        });

        let client_url = local_url.clone();
        let stream = TcpStream::connect(format!("127.0.0.1:{}", local_url.port().unwrap()))
            .await
            .unwrap();
        let socket = RuntimeTcpSocket::new(stream);
        let client_tunnel = upgrade_connected(socket, client_url, &payloads, &counter)
            .await
            .unwrap();

        let server_tunnel = server.await.unwrap();

        use easytier_core::packet::ZCPacket;
        use futures::{SinkExt, StreamExt};

        let (mut c_recv, mut c_send) = client_tunnel.split();
        let (mut s_recv, mut s_send) = server_tunnel.split();

        let data = b"hello fakehttp";
        let pkt = ZCPacket::new_with_payload(data);
        c_send.send(pkt).await.unwrap();

        let received = s_recv.next().await.unwrap().unwrap();
        assert_eq!(received.payload(), data);

        let reply = ZCPacket::new_with_payload(b"reply");
        s_send.send(reply).await.unwrap();

        let received = c_recv.next().await.unwrap().unwrap();
        assert_eq!(received.payload(), b"reply");
    }

    #[tokio::test]
    async fn fakehttp_http_pingpong() {
        test_pingpong(http_hosts(), 0).await;
    }

    #[tokio::test]
    async fn fakehttp_https_pingpong() {
        test_pingpong(https_hosts(), 0).await;
    }

    #[tokio::test]
    async fn fakehttp_no_payload_fails() {
        let payloads = parse_payloads(vec!["invalid_entry".to_string()]);
        let counter = AtomicUsize::new(0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let socket = RuntimeTcpSocket::new(stream);
        let result = upgrade_connected(
            socket,
            format!("fakehttp://127.0.0.1:{}", port).parse().unwrap(),
            &payloads,
            &counter,
        )
        .await;
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

    #[allow(dead_code)]
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

        if offset + 1 > body.len() {
            return None;
        }
        let comp_len = body[offset] as usize;
        offset += 1 + comp_len;

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
        assert!(ch.cipher_suites.contains(&0x1301), "should contain TLS_AES_128_GCM");
        assert!(ch.cipher_suites.contains(&0x1302), "should contain TLS_AES_256_GCM");
        assert!(ch.cipher_suites.contains(&0x1303), "should contain TLS_CHACHA20");
    }

    #[test]
    fn test_dpi_tls_extensions_presence() {
        let host = "www.google.com";
        let data = build_tls_client_hello(host);
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();
        let ch = parse_client_hello(body).unwrap();
        let ext = ch.extensions_raw;

        let sni = find_extension(ext, 0x0000).expect("should have SNI extension");
        let sni_str = std::str::from_utf8(&sni[5..]).unwrap_or("");
        assert_eq!(sni_str, host, "SNI hostname should match");
        assert!(find_extension(ext, 0x0033).is_some(), "should have key_share");
        assert!(find_extension(ext, 0x002b).is_some(), "should have supported_versions");

        let alpn = find_extension(ext, 0x0010).expect("should have ALPN");
        let alpn_str = String::from_utf8_lossy(alpn);
        assert!(alpn_str.contains("h2"), "ALPN should contain h2");
        assert!(find_extension(ext, 0x0023).is_some(), "should have session_ticket");
        assert!(find_extension(ext, 0x0005).is_some(), "should have status_request");

        let mut has_grease_ext = false;
        let mut offset = 0;
        while offset + 4 <= ext.len() {
            let ext_type = u16::from_be_bytes([ext[offset], ext[offset + 1]]);
            let ext_len = u16::from_be_bytes([ext[offset + 2], ext[offset + 3]]) as usize;
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
        assert!(data.len() >= 517, "ClientHello record should be >= 517 bytes (got {})", data.len());
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();
        assert!(body.len() >= 512, "ClientHello body should be >= 512 bytes (got {})", body.len());
    }

    #[test]
    fn test_dpi_tls_server_hello_compliance() {
        let client_sid: [u8; 32] = rand::random();
        let server_data = build_tls_server_hello(Some(&client_sid));
        let (_, _, payload) = parse_tls_record(&server_data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();

        assert!(body.len() > 70, "ServerHello body too short");
        let sid_len = body[34] as usize;
        assert_eq!(sid_len, 32);
        let server_sid = &body[35..35 + sid_len];
        assert_eq!(server_sid, &client_sid, "ServerHello should echo client session_id");

        let offset = 2 + 32 + 1 + sid_len + 2 + 1;
        assert!(body.len() > offset + 2, "ServerHello should have extensions");
        let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        assert!(ext_len > 0, "ServerHello extensions should not be empty");

        let ext_data = &body[offset + 2..offset + 2 + ext_len];
        assert!(find_extension(ext_data, 0x002b).is_some(), "should have supported_versions extension");
        assert!(find_extension(ext_data, 0x0033).is_some(), "should have key_share extension");
    }

    #[test]
    fn test_dpi_tls_randomness() {
        let data1 = build_tls_client_hello("example.com");
        let data2 = build_tls_client_hello("example.com");

        let (_, _, p1) = parse_tls_record(&data1).unwrap();
        let (_, _, p2) = parse_tls_record(&data2).unwrap();
        let (_, b1) = parse_handshake(p1).unwrap();
        let (_, b2) = parse_handshake(p2).unwrap();

        assert_ne!(&b1[2..34], &b2[2..34], "random should differ between calls");
        assert_ne!(&b1[35..67], &b2[35..67], "session_id should differ between calls");
    }

    #[test]
    fn test_dpi_tls_entropy() {
        let data = build_tls_client_hello("www.google.com");
        let (_, _, payload) = parse_tls_record(&data).unwrap();
        let (_, body) = parse_handshake(payload).unwrap();

        let random = &body[2..34];
        let entropy = shannon_entropy(random);
        assert!(entropy > 3.5, "random field entropy should be reasonable (got {:.2})", entropy);

        let encrypted: Vec<u8> = (0..1400).map(|_| rand::random::<u8>()).collect();
        let entropy = shannon_entropy(&encrypted);
        assert!(entropy > 7.8, "AES-like random data should have high entropy (got {:.2})", entropy);
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
        assert!(req_str.contains("Sec-WebSocket-Version: 13"), "should have WS version");
        assert!(req_str.contains("Sec-WebSocket-Key: "), "should have WS key");
        assert!(req_str.contains(&format!("Origin: http://{}", host)), "should have Origin");
        assert!(req_str.contains("Sec-WebSocket-Extensions: permessage-deflate"), "should have WS extensions");
        assert!(req_str.contains("Chrome/"), "should have Chrome User-Agent");
        assert!(req_str.contains("Pragma: no-cache"), "should have Pragma");
        assert!(req_str.contains("Cache-Control: no-cache"), "should have Cache-Control");
        assert_eq!(ws_key.len(), 24, "WS key should be 24 chars base64");
        assert!(req_str.contains(&ws_key), "returned key should match request");
    }

    #[test]
    fn test_dpi_http_response_format() {
        let ws_accept = compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==");
        let resp = build_http_response(&ws_accept);
        let resp_str = String::from_utf8_lossy(&resp);

        assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "should be 101 response");
        assert!(resp_str.ends_with("\r\n\r\n"), "should end with double CRLF");
        assert!(resp_str.contains("Connection: Upgrade"), "should have Connection: Upgrade");
        assert!(resp_str.contains("Upgrade: websocket"), "should have Upgrade: websocket");
        assert!(resp_str.contains(&format!("Sec-WebSocket-Accept: {}", ws_accept)), "should have computed WS Accept");
        assert!(resp_str.contains("Date:"), "should have Date header");
    }

    #[test]
    fn test_ws_accept_roundtrip() {
        let ws_key: [u8; 16] = rand::random();
        let key_b64 = BASE64_STANDARD.encode(ws_key);
        let accept = compute_ws_accept(&key_b64);
        assert!(!accept.is_empty());
        assert_ne!(accept, key_b64);
        assert_eq!(accept, compute_ws_accept(&key_b64));
    }

    #[tokio::test]
    async fn fakehttp_large_payload_transfer() {
        let payloads = parse_payloads(https_hosts());
        let counter = AtomicUsize::new(0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_url: url::Url =
            format!("fakehttp://127.0.0.1:{}", listener.local_addr().unwrap().port())
                .parse()
                .unwrap();

        let server_url = local_url.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = RuntimeTcpSocket::new(stream);
            upgrade_accepted(socket, server_url).await.unwrap()
        });

        let stream = TcpStream::connect(format!("127.0.0.1:{}", local_url.port().unwrap()))
            .await
            .unwrap();
        let socket = RuntimeTcpSocket::new(stream);
        let client_tunnel =
            upgrade_connected(socket, local_url, &payloads, &counter).await.unwrap();
        let server_tunnel = server.await.unwrap();

        use easytier_core::packet::ZCPacket;
        use futures::{SinkExt, StreamExt};

        let (mut c_recv, mut c_send) = client_tunnel.split();
        let (mut s_recv, mut s_send) = server_tunnel.split();

        // Send multiple packets of varying sizes
        let sizes = [1, 100, 500, 1000, 1500, TCP_MTU_BYTES - 100];
        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            c_send.send(ZCPacket::new_with_payload(&data)).await.unwrap();
            let received = s_recv.next().await.unwrap().unwrap();
            assert_eq!(received.payload(), data.as_slice(), "size={size}");
        }

        // Send in reverse direction
        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (255 - i % 256) as u8).collect();
            s_send.send(ZCPacket::new_with_payload(&data)).await.unwrap();
            let received = c_recv.next().await.unwrap().unwrap();
            assert_eq!(received.payload(), data.as_slice(), "reverse size={size}");
        }
    }

    #[tokio::test]
    async fn fakehttp_multiple_packets_streaming() {
        let payloads = parse_payloads(http_hosts());
        let counter = AtomicUsize::new(0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_url: url::Url =
            format!("fakehttp://127.0.0.1:{}", listener.local_addr().unwrap().port())
                .parse()
                .unwrap();

        let server_url = local_url.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = RuntimeTcpSocket::new(stream);
            upgrade_accepted(socket, server_url).await.unwrap()
        });

        let stream = TcpStream::connect(format!("127.0.0.1:{}", local_url.port().unwrap()))
            .await
            .unwrap();
        let socket = RuntimeTcpSocket::new(stream);
        let client_tunnel =
            upgrade_connected(socket, local_url, &payloads, &counter).await.unwrap();
        let server_tunnel = server.await.unwrap();

        use easytier_core::packet::ZCPacket;
        use futures::{SinkExt, StreamExt};

        let (_c_recv, mut c_send) = client_tunnel.split();
        let (mut s_recv, _) = server_tunnel.split();

        let packet_count = 50;
        for i in 0..packet_count {
            let data = format!("packet-{i:04}");
            c_send
                .send(ZCPacket::new_with_payload(data.as_bytes()))
                .await
                .unwrap();
        }

        for i in 0..packet_count {
            let received = s_recv.next().await.unwrap().unwrap();
            let expected = format!("packet-{i:04}");
            assert_eq!(received.payload(), expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn fakehttp_payload_round_robin() {
        let hosts = vec![
            "http://a.example.com".to_string(),
            "https://b.example.com".to_string(),
            "http://c.example.com".to_string(),
        ];
        let payloads = parse_payloads(hosts);
        assert_eq!(payloads.len(), 3);

        let counter = AtomicUsize::new(0);
        // Verify round-robin cycles
        for round in 0..2 {
            for i in 0..3 {
                let idx = counter.fetch_add(1, Ordering::Relaxed) % payloads.len();
                assert_eq!(idx, i, "round={round} i={i}");
            }
        }
    }

    #[tokio::test]
    async fn fakehttp_server_rejects_garbage() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let local_url: url::Url = format!("fakehttp://127.0.0.1:{port}").parse().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = RuntimeTcpSocket::new(stream);
            upgrade_accepted(socket, local_url).await
        });

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        // Send garbage that's neither HTTP nor TLS
        stream.write_all(b"\x00\x00\x00\x00extra").await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unrecognized protocol"));
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
