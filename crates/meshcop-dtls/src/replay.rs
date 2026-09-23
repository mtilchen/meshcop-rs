//! DTLS anti-replay window (RFC 6347 §4.1.2.6).

/// Sliding 64-record anti-replay window for one epoch.
///
/// Callers check [`Self::has_seen`] before authenticating a record and call
/// [`Self::mark_seen`] only after authentication succeeds, so forged records
/// cannot advance the window.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    newest_sequence: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    /// Creates an empty window that has seen no records.
    pub const fn new() -> Self {
        Self {
            newest_sequence: None,
            seen: 0,
        }
    }

    /// Returns whether `sequence` was already marked or is too old to track.
    pub fn has_seen(&self, sequence: u64) -> bool {
        let Some(newest) = self.newest_sequence else {
            return false;
        };
        if sequence > newest {
            return false;
        }
        let offset = newest - sequence;
        offset >= u64::BITS as u64 || ((self.seen >> offset) & 1) == 1
    }

    /// Marks an authenticated record's sequence number as received.
    pub fn mark_seen(&mut self, sequence: u64) {
        match self.newest_sequence {
            None => {
                self.newest_sequence = Some(sequence);
                self.seen = 1;
            }
            Some(newest) if sequence > newest => {
                let shift = sequence - newest;
                self.seen = if shift >= u64::BITS as u64 {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.newest_sequence = Some(sequence);
            }
            Some(newest) => {
                let offset = newest - sequence;
                if offset < u64::BITS as u64 {
                    self.seen |= 1 << offset;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayWindow;

    #[test]
    fn detects_in_window_replays_and_preserves_bits() {
        let mut window = ReplayWindow::new();
        assert!(!window.has_seen(100)); // empty window has seen nothing

        window.mark_seen(10);
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // future sequence
        assert!(!window.has_seen(9)); // older, never marked

        window.mark_seen(12); // newer: window slides left by two, bit 2 holds 10
        assert!(window.has_seen(12));
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // gap stays unseen
        assert!(!window.has_seen(9)); // beyond the marked bits, still unseen
        assert!(!window.has_seen(13)); // future

        window.mark_seen(11); // older within window: fills the gap
        assert!(window.has_seen(11));
        assert!(window.has_seen(10)); // neighbouring bits untouched
        assert!(window.has_seen(12));
    }

    #[test]
    fn handles_window_edges() {
        // An older sequence two positions back must set bit two, distinguishing
        // subtraction from division/addition in the offset computation.
        let mut window = ReplayWindow::default();
        window.mark_seen(20);
        window.mark_seen(18);
        assert!(window.has_seen(18));
        assert!(!window.has_seen(19));
        assert!(window.has_seen(20));

        // A jump of exactly the window width resets the bitmap to the newest
        // sequence only. The boundary checks keep the 64-bit shifts in range.
        let width = u64::BITS as u64;
        let mut window = ReplayWindow::new();
        window.mark_seen(1);
        window.mark_seen(1 + width); // shift == 64 resets rather than shifting
        assert!(window.has_seen(1 + width));
        assert!(window.has_seen(1)); // offset == 64 is treated as too old to trust
        assert!(!window.has_seen(2)); // within the fresh window but never marked
        window.mark_seen(1); // offset == 64 must be a no-op, not a 1 << 64 shift
        assert!(!window.has_seen(2));
    }

    #[test]
    fn remarking_a_seen_sequence_does_not_clear_its_bit() {
        // Re-marking an already-seen older sequence must leave its bit set
        // (`|=`), not toggle it off or wipe out its neighbours.
        let mut window = ReplayWindow::new();
        window.mark_seen(10);
        window.mark_seen(12); // seen = 0b101; bit 2 holds sequence 10
        window.mark_seen(10); // re-mark the already-set bit
        assert!(window.has_seen(10));
        assert!(window.has_seen(12));
    }
}
