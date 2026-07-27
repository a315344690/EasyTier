use std::cell::RefCell;

use rand::{RngCore, SeedableRng, rngs::SmallRng};

use crate::packet::ZCPacket;

pub const PADDING_LEN_SUFFIX_SIZE: usize = 2;
pub const DEFAULT_PADDING_MAX: u32 = 128;
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
