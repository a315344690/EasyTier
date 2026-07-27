use std::cell::RefCell;

use rand::{RngCore, SeedableRng, rngs::SmallRng};

use crate::tunnel::packet_def::ZCPacket;

pub const PADDING_LEN_SUFFIX_SIZE: usize = 2;
pub const DEFAULT_PADDING_MAX: u32 = 128;
// Budget ensures padding never causes faketcp frames to exceed common path MTUs.
// Worst case: path MTU 1400, IPv4, with disguise (WS client overhead 10 bytes)
// 1400 - IP(20) - TCP+TS(32) - disguise(10) = 1338 max TCP payload (inner)
// 1338 - AEAD(28) = 1310 max TCP-format buf after padding
// 1310 + NIC-to-TCP offset(16) = 1326 max NIC-format buf after padding
pub const PADDING_TOTAL_BUDGET: usize = 1326;

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

    #[test]
    fn test_padding_respects_budget() {
        // 1280 = default mtu, should fit within budget
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
        // NIC packet: buf_len = PAYLOAD_OFFSET_FOR_NIC(40) + payload
        // Budget limits buf_len in NIC format
        let payload = vec![0xCC; PADDING_TOTAL_BUDGET];
        let mut pkt = ZCPacket::new_with_payload(&payload);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        let pre_len = pkt.buf_len();

        add_padding(&mut pkt, 128);
        // When already over budget, only suffix is added
        assert_eq!(pkt.buf_len(), pre_len + PADDING_LEN_SUFFIX_SIZE);
        remove_padding(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), &payload[..]);
    }

    #[test]
    fn test_padding_small_packet_gets_padding() {
        let payload = vec![0xAA; 100];
        let mut pkt = ZCPacket::new_with_payload(&payload);
        pkt.fill_peer_manager_hdr(1, 2, 0);
        let pre_len = pkt.buf_len();

        // Small packet should have room for substantial padding
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
        // Simulate the full path: padding → encrypt(+28) → convert NIC→TCP(-16)
        // → IP+TCP overhead → must fit in path MTU 1400
        const AEAD_TAIL_SIZE: usize = 28;
        const NIC_TO_TCP_SHRINK: usize = 16;
        const IP_TCP_OVERHEAD: usize = 20 + 32; // IP + TCP+TS
        const PATH_MTU: usize = 1400;

        let large_payload = vec![0xAB; 1280]; // default mtu
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
