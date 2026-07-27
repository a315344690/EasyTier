#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow<const N: usize> {
    max_seq: u64,
    head: usize,
    bitmap: [u8; N],
    valid: bool,
}

impl<const N: usize> Default for ReplayWindow<N> {
    fn default() -> Self {
        Self {
            max_seq: 0,
            head: 0,
            bitmap: [0u8; N],
            valid: false,
        }
    }
}

impl<const N: usize> ReplayWindow<N> {
    const WINDOW_SIZE: usize = N * 8;

    fn bit_index(&self, offset_from_head: usize) -> (usize, u8) {
        let idx = (self.head + Self::WINDOW_SIZE - offset_from_head) % Self::WINDOW_SIZE;
        let byte = idx / 8;
        let bit = idx % 8;
        (byte, 1u8 << bit)
    }

    fn test_bit_at_offset(&self, offset_from_head: usize) -> bool {
        let (byte, mask) = self.bit_index(offset_from_head);
        (self.bitmap[byte] & mask) != 0
    }

    fn set_bit_at_offset(&mut self, offset_from_head: usize) {
        let (byte, mask) = self.bit_index(offset_from_head);
        self.bitmap[byte] |= mask;
    }

    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.valid {
            self.valid = true;
            self.max_seq = seq;
            self.head = 0;
            self.bitmap.fill(0);
            self.set_bit_at_offset(0);
            return true;
        }

        if seq > self.max_seq {
            let advance = (seq - self.max_seq) as usize;
            if advance >= Self::WINDOW_SIZE {
                self.bitmap.fill(0);
                self.head = 0;
            } else {
                for i in 1..=advance {
                    let idx = (self.head + i) % Self::WINDOW_SIZE;
                    let byte = idx / 8;
                    let bit = idx % 8;
                    self.bitmap[byte] &= !(1u8 << bit);
                }
                self.head = (self.head + advance) % Self::WINDOW_SIZE;
            }
            self.max_seq = seq;
            self.set_bit_at_offset(0);
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        if delta >= Self::WINDOW_SIZE {
            return false;
        }
        if self.test_bit_at_offset(delta) {
            return false;
        }
        self.set_bit_at_offset(delta);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_always_accepted() {
        let mut w = ReplayWindow::<8>::default();
        assert!(w.accept(42));
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::<8>::default();
        assert!(w.accept(1));
        assert!(!w.accept(1));
    }

    #[test]
    fn sequential_all_accepted() {
        let mut w = ReplayWindow::<8>::default();
        for i in 0..200 {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::<8>::default();
        assert!(w.accept(10));
        assert!(w.accept(8));
        assert!(w.accept(9));
        assert!(w.accept(7));
        assert!(!w.accept(8));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::<8>::default();
        // window size = 8 * 8 = 64
        assert!(w.accept(0));
        assert!(w.accept(100));
        // seq 0 is now 100 behind max, window is 64 → rejected
        assert!(!w.accept(0));
        // seq 36 is exactly 64 behind → rejected
        assert!(!w.accept(36));
        // seq 37 is 63 behind → accepted
        assert!(w.accept(37));
    }

    #[test]
    fn large_jump_resets_window() {
        let mut w = ReplayWindow::<8>::default();
        assert!(w.accept(0));
        assert!(w.accept(1));
        // jump far beyond window
        assert!(w.accept(1000));
        // old values rejected
        assert!(!w.accept(0));
        assert!(!w.accept(1));
        // new values near 1000 accepted
        assert!(w.accept(999));
        assert!(w.accept(998));
    }

    #[test]
    fn wrapping_sequence_numbers() {
        let mut w = ReplayWindow::<8>::default();
        let base = u32::MAX as u64 - 10;
        for i in 0..20 {
            assert!(w.accept(base + i), "seq {} should be accepted", base + i);
        }
    }

    #[test]
    fn window_boundary_exact() {
        let mut w = ReplayWindow::<4>::default();
        // window size = 4 * 8 = 32
        assert!(w.accept(0));
        assert!(w.accept(31));
        // seq 0 is exactly 31 behind max_seq (31), within window of 32
        assert!(!w.accept(0)); // already seen
        // advance to 32
        assert!(w.accept(32));
        // seq 0 is 32 behind max_seq (32), delta == WINDOW_SIZE → rejected
        assert!(!w.accept(0));
    }
}
