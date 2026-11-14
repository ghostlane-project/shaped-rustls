use alloc::vec::Vec;
use core::mem;
use core::ops::Range;
#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "std")]
use crate::msgs::message::MAX_WIRE_SIZE;

/// The read offered to a deframer buffer that holds nothing.
#[cfg(feature = "std")]
pub(crate) const READ_SIZE: usize = 4096;

/// Conversion from a slice within a larger buffer into
/// a `Range` offset within.
#[derive(Debug)]
pub(crate) struct Locator {
    bounds: Range<*const u8>,
}

impl Locator {
    #[inline]
    pub(crate) fn new(slice: &[u8]) -> Self {
        Self {
            bounds: slice.as_ptr_range(),
        }
    }

    #[inline]
    pub(crate) fn locate(&self, slice: &[u8]) -> Range<usize> {
        let bounds = slice.as_ptr_range();
        debug_assert!(self.fully_contains(slice));
        let start = bounds.start as usize - self.bounds.start as usize;
        let len = bounds.end as usize - bounds.start as usize;
        Range {
            start,
            end: start + len,
        }
    }

    #[inline]
    pub(crate) fn fully_contains(&self, slice: &[u8]) -> bool {
        let bounds = slice.as_ptr_range();
        bounds.start >= self.bounds.start && bounds.end <= self.bounds.end
    }
}

/// Conversion from a `Range` offset to the original slice.
pub(crate) struct Delocator<'b> {
    slice: &'b [u8],
}

impl<'b> Delocator<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn slice_from_range(&'_ self, range: &Range<usize>) -> &'b [u8] {
        // safety: this unwrap is safe so long as `range` came from `locate()`
        // for the same buffer
        self.slice.get(range.clone()).unwrap()
    }

    #[inline]
    pub(crate) fn locator(self) -> Locator {
        Locator::new(self.slice)
    }
}

/// Reordering the underlying buffer based on ranges.
pub(crate) struct Coalescer<'b> {
    slice: &'b mut [u8],
}

impl<'b> Coalescer<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b mut [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn copy_within(&mut self, from: Range<usize>, to: Range<usize>) {
        debug_assert!(from.len() == to.len());
        debug_assert!(self.slice.get(from.clone()).is_some());
        debug_assert!(self.slice.get(to.clone()).is_some());
        self.slice.copy_within(from, to.start);
    }

    #[inline]
    pub(crate) fn delocator(self) -> Delocator<'b> {
        Delocator::new(self.slice)
    }
}

/// Accounting structure tracking progress in parsing a single buffer.
#[derive(Clone, Debug)]
pub(crate) struct BufferProgress {
    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl BufferProgress {
    pub(super) fn new(processed: usize) -> Self {
        Self {
            processed,
            discard: 0,
        }
    }

    #[inline]
    pub(crate) fn add_discard(&mut self, discard: usize) {
        self.discard += discard;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self
            .processed
            .saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,
}

impl DeframerVecBuffer {
    /// Discard `taken` bytes from the start of our buffer.
    pub(crate) fn discard(&mut self, taken: usize) {
        #[allow(clippy::comparison_chain)]
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf
                .copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken >= self.used {
            self.used = 0;
        }
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    /// Bytes the buffer holds allocated, used or not.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Read some bytes from `rd`, and add them to the buffer.
    pub(crate) fn read(&mut self, rd: &mut dyn io::Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(&mut self.buf[self.used..])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        /// TLS allows for handshake messages of up to 16MB.  We
        /// restrict that to 64KB to limit potential for denial-of-
        /// service.
        const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // Grow the buffer to the full window up front for application data so
        // each socket read can pull a whole record (plus change) in one call;
        // handshake buffering keeps the incremental 4k sizing to bound memory.
        // Unlike upstream, do not shrink an empty buffer back down: in steady
        // state the buffer empties after every processed record batch, and the
        // shrink-regrow cycle costs a realloc plus zeroing per batch. After
        // dealing with a large handshake message (exceeding
        // `OutboundOpaqueMessage::MAX_WIRE_SIZE`), reduce the buffer size
        // again (large messages should be rare).
        let need_capacity = match is_joining_hs {
            true => Ord::min(allow_max, self.used + READ_SIZE),
            false => allow_max,
        };
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.buf.len() > allow_max {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        Ok(())
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Range<usize> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub(crate) struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

impl<'a> DeframerSliceBuffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub(crate) fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    pub(crate) fn pending_discard(&self) -> usize {
        self.discard
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard..]
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// A TLS 1.3 record at the largest size a peer sends: 16 KiB of plaintext,
    /// its content type and a 16-byte tag.
    const FULL_RECORD_PAYLOAD: usize = 16_384 + 1 + 16;

    /// An application-data record with `payload_len` bytes of payload.
    fn record(payload_len: usize) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload_len);
        record.extend_from_slice(&[0x17, 0x03, 0x03]);
        record.extend_from_slice(&(payload_len as u16).to_be_bytes());
        record.extend((0..payload_len).map(|i| (i % 251) as u8));
        record
    }

    /// Reads `bytes` into `buf` as a socket would deliver them: in `pieces`
    /// (the last one repeated), each read taking at most what the buffer
    /// offers. Between reads nothing is discarded, as when
    /// `process_new_packets()` finds only a partial record.
    fn read_in_pieces(buf: &mut DeframerVecBuffer, bytes: &[u8], pieces: &[usize]) {
        let mut offset = 0;
        let mut pieces = pieces.iter().copied();
        let mut piece = 0;
        while offset < bytes.len() {
            piece = pieces.next().unwrap_or(piece);
            let end = Ord::min(bytes.len(), offset.saturating_add(piece));
            while offset < end {
                let n = buf
                    .read(&mut &bytes[offset..end], false)
                    .unwrap();
                assert!(
                    n > 0,
                    "the buffer offered no room at {offset} of {}",
                    bytes.len()
                );
                offset += n;
                buf.discard(0);
                assert_eq!(buf.filled(), &bytes[..offset]);
            }
        }
    }

    #[test]
    fn drained_buffer_holds_no_allocation() {
        let mut buf = DeframerVecBuffer::default();
        let full = record(FULL_RECORD_PAYLOAD);
        read_in_pieces(&mut buf, &full, &[usize::MAX]);
        assert!(buf.capacity() >= full.len());

        buf.discard(full.len());
        assert!(buf.filled().is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn empty_buffer_offers_a_small_read_then_the_rest_of_the_record() {
        let mut buf = DeframerVecBuffer::default();
        let full = record(FULL_RECORD_PAYLOAD);

        let first = buf.read(&mut &full[..], false).unwrap();
        assert_eq!(first, READ_SIZE);
        assert!(buf.capacity() <= READ_SIZE);

        // The rest of the record comes in one read.
        let rest = buf
            .read(&mut &full[first..], false)
            .unwrap();
        assert_eq!(first + rest, full.len());
        assert_eq!(buf.filled(), &full[..]);
    }

    #[test]
    fn largest_record_arrives_in_pieces_after_release() {
        let mut buf = DeframerVecBuffer::default();
        let full = record(FULL_RECORD_PAYLOAD);
        read_in_pieces(&mut buf, &full, &[usize::MAX]);
        buf.discard(full.len());
        assert_eq!(buf.capacity(), 0);

        // A 16 KiB record, its header split, then pieces across the small read.
        read_in_pieces(&mut buf, &full, &[1, 4, 3, 4_093, 5_000, 1, usize::MAX]);
        buf.discard(full.len());
        assert_eq!(buf.capacity(), 0);

        // The largest record the deframer takes, MAX_WIRE_SIZE bytes on the wire.
        let largest = record(MAX_WIRE_SIZE - 5);
        read_in_pieces(&mut buf, &largest, &[2, 4_096, 7, 1_000]);
        assert_eq!(buf.filled().len(), MAX_WIRE_SIZE);
        buf.discard(largest.len());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn partly_consumed_buffer_keeps_the_rest() {
        let mut buf = DeframerVecBuffer::default();
        let mut two = record(FULL_RECORD_PAYLOAD);
        let second = record(300);
        two.extend_from_slice(&second);
        read_in_pieces(&mut buf, &two, &[usize::MAX]);

        buf.discard(two.len() - second.len());
        assert_eq!(buf.filled(), &second[..]);
        assert!(buf.capacity() >= second.len());

        buf.discard(second.len());
        assert_eq!(buf.capacity(), 0);
    }
}
