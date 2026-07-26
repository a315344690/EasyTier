use std::cell::RefCell;

use rand::{RngCore, SeedableRng, rngs::SmallRng};

use crate::tunnel::packet_def::ZCPacket;

pub const PADDING_LEN_SUFFIX_SIZE: usize = 2;
pub const DEFAULT_PADDING_MAX: u32 = 128;

thread_local! {
    static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_rng(rand::thread_rng()).unwrap());
}

pub fn effective_padding_max(config_value: u32) -> u32 {
    if config_value == 0 {
        DEFAULT_PADDING_MAX
    } else {
        config_value
    }
}

pub fn add_padding(pkt: &mut ZCPacket, max_padding: u32) {
    let clamped = max_padding.min(u16::MAX as u32);
    let padding_len = if clamped == 0 {
        0u16
    } else {
        PADDING_RNG.with(|rng| (rng.borrow_mut().next_u32() % (clamped + 1)) as u16)
    };

    let buf = pkt.mut_inner();
    if padding_len > 0 {
        let start = buf.len();
        buf.resize(start + padding_len as usize, 0);
        PADDING_RNG.with(|rng| rng.borrow_mut().fill_bytes(&mut buf[start..]));
    }
    buf.extend_from_slice(&padding_len.to_le_bytes());
}

pub fn remove_padding(pkt: &mut ZCPacket) -> Result<(), crate::peers::encrypt::Error> {
    let payload_len = pkt.payload_len();
    if payload_len < PADDING_LEN_SUFFIX_SIZE {
        return Err(crate::peers::encrypt::Error::PacketTooShort(payload_len));
    }

    let buf_len = pkt.buf_len();
    let inner = pkt.mut_inner();
    let padding_len = u16::from_le_bytes([inner[buf_len - 2], inner[buf_len - 1]]) as usize;

    let total_overhead = padding_len + PADDING_LEN_SUFFIX_SIZE;
    if payload_len < total_overhead {
        return Err(crate::peers::encrypt::Error::PacketTooShort(payload_len));
    }

    inner.truncate(buf_len - total_overhead);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_roundtrip() {
        let payload = b"hello world test data";
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(1, 2, 0);

        add_padding(&mut pkt, 128);
        assert!(pkt.buf_len() > payload.len());

        remove_padding(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), payload);
    }

    #[test]
    fn test_padding_zero_max() {
        let payload = b"no padding";
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        let original_len = pkt.buf_len();

        add_padding(&mut pkt, 0);
        assert_eq!(pkt.buf_len(), original_len + PADDING_LEN_SUFFIX_SIZE);

        remove_padding(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), payload);
    }

    #[test]
    fn test_padding_varies() {
        let payload = b"test";
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..100 {
            let mut pkt = ZCPacket::new_with_payload(payload);
            pkt.fill_peer_manager_hdr(1, 2, 0);
            add_padding(&mut pkt, 128);
            lengths.insert(pkt.buf_len());
        }
        assert!(lengths.len() > 1);
    }

    #[test]
    fn test_remove_padding_too_short() {
        let mut pkt = ZCPacket::new_with_payload(&[]);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        assert!(remove_padding(&mut pkt).is_err());
    }

    #[test]
    fn test_remove_padding_corrupted_length() {
        // Manually craft a packet with an invalid padding_len that exceeds payload
        let mut pkt = ZCPacket::new_with_payload(&[0x00, 0x00]);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        // Overwrite the last 2 bytes to claim 255 bytes of padding
        let buf_len = pkt.buf_len();
        let inner = pkt.mut_inner();
        inner[buf_len - 2] = 0xFF;
        inner[buf_len - 1] = 0x00; // padding_len = 255, but payload is only 2 bytes
        assert!(remove_padding(&mut pkt).is_err());
    }

    #[test]
    fn test_effective_padding_max() {
        assert_eq!(effective_padding_max(0), DEFAULT_PADDING_MAX);
        assert_eq!(effective_padding_max(64), 64);
        assert_eq!(effective_padding_max(1), 1);
        assert_eq!(effective_padding_max(1000), 1000);
    }
}
