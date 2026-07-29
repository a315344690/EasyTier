use std::cell::RefCell;

use rand::{RngCore, SeedableRng, rngs::SmallRng};

use crate::packet::ZCPacket;

pub const PADDING_LEN_SUFFIX_SIZE: usize = 2;
pub const DEFAULT_PADDING_MAX: u32 = 128;
pub const PADDING_TOTAL_BUDGET: usize = 1326;

thread_local! {
    static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_rng(rand::thread_rng()).unwrap());
}


pub fn add_padding(pkt: &mut ZCPacket, max_padding: u32) {
    let clamped = max_padding.min(u16::MAX as u32);
    PADDING_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();

        let current_size = pkt.buf_len();
        let available = PADDING_TOTAL_BUDGET
            .saturating_sub(current_size)
            .saturating_sub(PADDING_LEN_SUFFIX_SIZE);
        let effective_max = (clamped as usize).min(available) as u32;

        let padding_len = if effective_max == 0 {
            0u16
        } else {
            (rng.next_u32() % (effective_max + 1)) as u16
        };

        let buf = pkt.mut_inner();
        if padding_len > 0 {
            let start = buf.len();
            buf.resize(start + padding_len as usize, 0);
            rng.fill_bytes(&mut buf[start..]);
        }
        buf.extend_from_slice(&padding_len.to_le_bytes());
    });
}

pub fn remove_padding(pkt: &mut ZCPacket) -> Result<(), super::encrypt::Error> {
    let payload_len = pkt.payload_len();
    if payload_len < PADDING_LEN_SUFFIX_SIZE {
        return Err(super::encrypt::Error::PacketTooShort(payload_len));
    }

    let buf_len = pkt.buf_len();
    let inner = pkt.mut_inner();
    let padding_len = u16::from_le_bytes([inner[buf_len - 2], inner[buf_len - 1]]) as usize;

    let total_overhead = padding_len + PADDING_LEN_SUFFIX_SIZE;
    if payload_len < total_overhead {
        return Err(super::encrypt::Error::PacketTooShort(payload_len));
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
        let mut pkt = ZCPacket::new_with_payload(&[0x00, 0x00]);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        let buf_len = pkt.buf_len();
        let inner = pkt.mut_inner();
        inner[buf_len - 2] = 0xFF;
        inner[buf_len - 1] = 0x00;
        assert!(remove_padding(&mut pkt).is_err());
    }



    #[test]
    fn test_padding_respects_budget() {
        let large_payload = vec![0xAB; 1280];
        for _ in 0..200 {
            let mut pkt = ZCPacket::new_with_payload(&large_payload);
            pkt.fill_peer_manager_hdr(1, 2, 0);
            add_padding(&mut pkt, DEFAULT_PADDING_MAX);
            assert!(
                pkt.buf_len() <= PADDING_TOTAL_BUDGET,
                "buf_len {} exceeded budget {}",
                pkt.buf_len(),
                PADDING_TOTAL_BUDGET
            );
            remove_padding(&mut pkt).unwrap();
            assert_eq!(pkt.payload(), &large_payload[..]);
        }
    }

    #[test]
    fn test_padding_never_exceeds_budget() {
        let payload = vec![0xCC; PADDING_TOTAL_BUDGET];
        let mut pkt = ZCPacket::new_with_payload(&payload);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        let pre_len = pkt.buf_len();

        add_padding(&mut pkt, 128);
        assert_eq!(pkt.buf_len(), pre_len + PADDING_LEN_SUFFIX_SIZE);
        remove_padding(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), &payload[..]);
    }

    #[test]
    fn test_padding_small_packet_gets_padding() {
        let payload = vec![0xAA; 100];
        let pre_len = {
            let mut pkt = ZCPacket::new_with_payload(&payload);
            pkt.fill_peer_manager_hdr(1, 2, 0);
            pkt.buf_len()
        };

        let mut got_nonzero = false;
        for _ in 0..50 {
            let mut pkt = ZCPacket::new_with_payload(&payload);
            pkt.fill_peer_manager_hdr(1, 2, 0);
            add_padding(&mut pkt, DEFAULT_PADDING_MAX);
            assert!(pkt.buf_len() <= PADDING_TOTAL_BUDGET);
            if pkt.buf_len() > pre_len + PADDING_LEN_SUFFIX_SIZE {
                got_nonzero = true;
            }
            remove_padding(&mut pkt).unwrap();
            assert_eq!(pkt.payload(), &payload[..]);
        }
        assert!(got_nonzero, "small packets should get non-zero padding");
    }

    #[test]
    fn test_faketcp_mtu_safety() {
        const AEAD_TAIL_SIZE: usize = 28;
        const NIC_TO_TCP_SHRINK: usize = 16;
        const IP_TCP_OVERHEAD: usize = 20 + 32;
        const PATH_MTU: usize = 1400;

        let large_payload = vec![0xAB; 1280];
        for _ in 0..1000 {
            let mut pkt = ZCPacket::new_with_payload(&large_payload);
            pkt.fill_peer_manager_hdr(1, 2, 0);
            add_padding(&mut pkt, DEFAULT_PADDING_MAX);

            let tcp_buf_len = pkt.buf_len() - NIC_TO_TCP_SHRINK;
            let post_encrypt_size = tcp_buf_len + AEAD_TAIL_SIZE;
            let ip_packet_size = IP_TCP_OVERHEAD + post_encrypt_size;
            assert!(
                ip_packet_size <= PATH_MTU,
                "IP packet {} would exceed path MTU {} (nic_buf={}, tcp_buf={}, encrypted={})",
                ip_packet_size,
                PATH_MTU,
                pkt.buf_len(),
                tcp_buf_len,
                post_encrypt_size
            );
        }
    }
}
