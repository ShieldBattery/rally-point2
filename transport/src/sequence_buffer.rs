//! A ring buffer for tracking information about sent and received packets.
//!
//! Ported essentially verbatim from `shieldbattery/game/src/netcode/sequence_buffer.rs`.

const SIGN_BIT: u64 = 0x8000_0000_0000_0000;

/// A ring buffer designed for storing information about packets that have been sent and received.
/// This is similar to the data structure described here:
/// <https://gafferongames.com/post/reliable_ordered_messages/>
///
/// As a notable difference, this uses 63-bit sequence identifiers rather than 16-bit ones, which
/// simplifies the logic greatly as we can assume the sequence identifiers will not wrap during
/// a connection. This does have a trade-off in the amount of data sent in each packet if numbers
/// get very large, although this could in the future be offset by using QUIC-like packet number
/// abbreviation.
pub struct SequenceBuffer<T: Clone + Default> {
    entries: Box<[T]>,
    // NOTE(tec27): i64 is a small optimization over an Option<u64>. We use the sign bit as an
    // indicator that a slot is empty, which saves 4 bytes at the expense of losing 1 bit of
    // possible values.
    entry_sequences: Box<[i64]>,
    sequence: u64,
}

#[allow(dead_code)]
impl<T: Clone + Default> SequenceBuffer<T> {
    pub fn with_capacity(size: usize) -> Self {
        Self {
            entries: vec![T::default(); size].into_boxed_slice(),
            entry_sequences: vec![-1; size].into_boxed_slice(),
            sequence: 0,
        }
    }

    /// Returns the current sequence number (which would be the next free sequence number to insert
    /// at for new packets).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns whether a particular sequence number has an entry in the buffer.
    pub fn exists(&self, sequence: u64) -> bool {
        let index = self.index(sequence);
        self.entry_sequences[index] == sequence as i64
    }

    /// Returns a reference to the entry with the provided sequence number, if it exists.
    pub fn get(&self, sequence: u64) -> Option<&T> {
        let index = self.index(sequence);

        if self.entry_sequences[index] == sequence as i64 {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the entry with the provided sequence number, if it exists.
    pub fn get_mut(&mut self, sequence: u64) -> Option<&mut T> {
        let index = self.index(sequence);

        if self.entry_sequences[index] == sequence as i64 {
            Some(&mut self.entries[index])
        } else {
            None
        }
    }

    /// Inserts `entry` into the buffer at `sequence`. Data older than 1 capacity of the buffer
    /// will not be inserted and `None` will be returned.
    pub fn insert(&mut self, sequence: u64, entry: T) -> Option<&mut T> {
        assert_eq!(sequence & SIGN_BIT, 0);

        if sequence < self.sequence && self.sequence - sequence >= self.entry_sequences.len() as u64
        {
            // Old sequence number, ignore the data
            return None;
        }

        self.advance_to(sequence);

        let index = self.index(sequence);
        self.entry_sequences[index] = sequence as i64;
        self.entries[index] = entry;

        Some(&mut self.entries[index])
    }

    pub fn remove(&mut self, sequence: u64) -> Option<T> {
        assert_eq!(sequence & SIGN_BIT, 0);

        let index = self.index(sequence);
        if self.entry_sequences[index] == sequence as i64 {
            let value = std::mem::take(&mut self.entries[index]);
            self.entry_sequences[index] = -1;
            return Some(value);
        }

        None
    }

    /// Advances the current sequence number if the target number is a forward move. Any entries
    /// between the old position and the new position will be cleared (as these would be slots from
    /// a previous rotation).
    fn advance_to(&mut self, sequence: u64) {
        assert_eq!((sequence + 1) & SIGN_BIT, 0);

        if sequence + 1 > self.sequence {
            self.remove_entries_inclusive(self.sequence, sequence);
            self.sequence = sequence + 1;
        }
    }

    /// Removes entries between `first_sequence` and `last_sequence`, inclusive.
    fn remove_entries_inclusive(&mut self, first_sequence: u64, last_sequence: u64) {
        assert_eq!(first_sequence & SIGN_BIT, 0);
        assert_eq!(last_sequence & SIGN_BIT, 0);

        if last_sequence < first_sequence {
            return;
        }

        if last_sequence - first_sequence >= self.entries.len() as u64 {
            // At least one full rotation, so we can just remove everything
            for index in 0..self.entry_sequences.len() {
                self.entry_sequences[index] = -1;
                self.entries[index] = T::default();
            }
        } else {
            for sequence in first_sequence..=last_sequence {
                self.remove(sequence);
            }
        }
    }

    fn index(&self, sequence: u64) -> usize {
        assert_eq!(sequence & SIGN_BIT, 0);
        (sequence % self.entries.len() as u64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceBuffer;

    #[derive(Clone, Default)]
    struct Data(u64);

    /// Inserting a run of seqs leaves the ring holding the newest `capacity`
    /// of them and nothing else: an exact fill, a run that starts above zero
    /// (so the ring rotates onto it), and a run that overruns the ring and
    /// overwrites its own oldest entries.
    #[test]
    fn inserting_a_run_keeps_the_newest_capacity_entries() {
        // (case, first seq, how many, a seq that must be present afterwards,
        //  seqs that must not be)
        let cases: [(&str, u64, u64, u64, &[u64]); 3] = [
            ("an exact fill", 0, 4, 0, &[4, 8]),
            ("a run starting above zero", 2, 4, 2, &[0, 8]),
            ("a run that overruns the ring", 0, 6, 2, &[0, 8]),
        ];

        for (case, start, count, present, absent) in cases {
            let mut buffer: SequenceBuffer<Data> = SequenceBuffer::with_capacity(4);
            for i in start..start + count {
                buffer.insert(i, Data(i));
            }

            assert_eq!(count_entries(&buffer), 4, "{case}");
            assert!(buffer.exists(present), "{case}: {present} was overwritten");
            for &gone in absent {
                assert!(!buffer.exists(gone), "{case}: {gone} should not be present");
            }
        }
    }

    #[test]
    fn insert_into_buffer_old_entry() {
        let mut buffer = SequenceBuffer::with_capacity(8);
        buffer.insert(9, Data(9));
        let value = buffer.insert(8, Data(8));
        assert!(value.is_some());

        // overlaps with the previous insert, but is older, so it should not be inserted
        let value = buffer.insert(0, Data(0));
        assert!(value.is_none());
        assert!(!buffer.exists(0));
        assert_eq!(buffer.get(8).unwrap().0, 8);

        // overlaps but is newer, so should be inserted
        let value = buffer.insert(24, Data(24));
        assert!(value.is_some());
        assert!(buffer.exists(24));
        assert_eq!(buffer.get(24).unwrap().0, 24);

        // the last insert should have rotated the data structure completely, so the old 9 entry
        // should have been removed
        assert_eq!(count_entries(&buffer), 1);
    }

    #[test]
    fn remove_from_buffer() {
        let mut buffer = SequenceBuffer::with_capacity(4);
        buffer.insert(6, Data(6));
        let removed = buffer.remove(6);

        assert_eq!(removed.unwrap().0, 6);
        assert!(!buffer.exists(6));

        let removed = buffer.remove(8);
        assert!(removed.is_none());
    }

    fn count_entries(buffer: &SequenceBuffer<Data>) -> usize {
        buffer.entry_sequences.iter().filter(|&&p| p >= 0).count()
    }
}
