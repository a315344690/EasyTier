/// Ring-buffer based sliding window for packet deduplication.
/// Window capacity = N * 8 bits. O(1) for normal in-order traffic.
#[derive(Debug, Clone)]
pub struct ReplayWindow<const N: usize> {
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

    pub fn clear(&mut self) {
        self.max_seq = 0;
        self.head = 0;
        self.bitmap.fill(0);
        self.valid = false;
    }

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

    /// Check if seq is acceptable (not a replay) and mark it as seen.
    /// Returns true if accepted, false if rejected (duplicate or too old).
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

    /// Read-only check without marking. Returns true if the seq would be accepted.
    pub fn can_accept(&self, seq: u64) -> bool {
        if !self.valid || seq > self.max_seq {
            return true;
        }
        let delta = (self.max_seq - seq) as usize;
        delta < Self::WINDOW_SIZE && !self.test_bit_at_offset(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_accept() {
        let mut w = ReplayWindow::<4>::default(); // 32-bit window
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(w.accept(3));
        // Duplicate rejection
        assert!(!w.accept(1));
        assert!(!w.accept(2));
        assert!(!w.accept(3));
    }

    #[test]
    fn test_out_of_order() {
        let mut w = ReplayWindow::<4>::default(); // 32-bit window
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(w.accept(1));
        assert!(w.accept(4));
        assert!(w.accept(2));
        // All should now be duplicates
        assert!(!w.accept(1));
        assert!(!w.accept(5));
    }

    #[test]
    fn test_window_overflow() {
        let mut w = ReplayWindow::<4>::default(); // 32-bit window
        assert!(w.accept(1));
        // Jump past window
        assert!(w.accept(100));
        // seq 1 is now outside window, should be rejected
        assert!(!w.accept(1));
        // But seq 100-31=69 and above should work if not seen
        assert!(w.accept(69));
        // seq 68 is outside window (100 - 68 = 32 >= WINDOW_SIZE=32)
        assert!(!w.accept(68));
    }

    #[test]
    fn test_sequential_traffic() {
        let mut w = ReplayWindow::<32>::default(); // 256-bit window
        for i in 1..=1000u64 {
            assert!(w.accept(i));
        }
        // Recent packets should be rejected
        for i in 745..=1000u64 {
            assert!(!w.accept(i));
        }
        // Old packets outside window should be rejected
        assert!(!w.accept(1));
        assert!(!w.accept(744));
    }

    #[test]
    fn test_large_window() {
        let mut w = ReplayWindow::<8192>::default(); // 65536-bit window
        assert!(w.accept(1));
        assert!(w.accept(65537)); // large jump
        assert!(!w.accept(1)); // too old
        assert!(w.accept(2)); // still within window (65537 - 2 = 65535 < 65536)
        assert!(!w.accept(2)); // duplicate
    }

    #[test]
    fn test_can_accept() {
        let mut w = ReplayWindow::<4>::default(); // 32-bit window
        assert!(w.can_accept(1));
        assert!(w.accept(1));
        assert!(!w.can_accept(1));
        assert!(w.can_accept(2));
        assert!(w.can_accept(100));
    }

    #[test]
    fn test_clear() {
        let mut w = ReplayWindow::<4>::default();
        assert!(w.accept(50));
        assert!(!w.accept(50));
        w.clear();
        assert!(w.accept(50));
    }

    #[test]
    fn test_wrap_around_ring() {
        let mut w = ReplayWindow::<4>::default(); // 32-bit window
        // Fill the window by advancing one at a time
        for i in 1..=64u64 {
            assert!(w.accept(i));
        }
        // All recent should be duplicates
        for i in 33..=64u64 {
            assert!(!w.accept(i));
        }
        // Old ones outside window
        assert!(!w.accept(1));
        assert!(!w.accept(32));
    }
}
