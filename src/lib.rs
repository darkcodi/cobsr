#![no_std]

//! # COBSIN - COBS In-Place Encoding/Decoding
//!
//! This library provides in-place COBS (Consistent Overhead Byte Stuffing) encoding
//! and decoding for `no_std` environments.
//!
//! ## Overview
//!
//! COBS is an algorithm that transforms data to eliminate zero bytes, making it
//! suitable for packet-based protocols where zeros are used as delimiters.
//!
//! ## Features
//!
//! - `no_std` compatible - works in embedded and bare-metal environments
//! - In-place encoding and decoding - minimal memory overhead
//! - Zero allocations - no heap required
//!
//! ## Functions
//!
//! - [`cobs_encode_in_place`] - Encode data in-place, returning the new length
//! - [`cobs_decode_in_place`] - Decode COBS data in-place, returning the original length
//! - [`max_overhead`] - Calculate maximum overhead for a given buffer size
//! - [`required_buf_len`] - Calculate the required buffer size for encoding
//!
//! ## Example
//!
//! ```rust
//! use cobsin::{cobs_encode_in_place, cobs_decode_in_place};
//!
//! let data = *b"Hello\x00World";
//! let input_len = data.len();
//!
//! // Buffer must be large enough: use a fixed-size array or Vec
//! let mut buf = [0u8; 32];
//! buf[..input_len].copy_from_slice(&data);
//!
//! // Encode
//! let encoded_len = cobs_encode_in_place(&mut buf, input_len).unwrap();
//!
//! // Decode
//! let decoded_len = cobs_decode_in_place(&mut buf, encoded_len).unwrap();
//! assert_eq!(&buf[..decoded_len], b"Hello\x00World");
//! ```

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDataLength,
    BufferTooSmall,
}

pub fn max_overhead(buf_len: usize) -> usize {
    buf_len.div_ceil(254)
}

pub fn required_buf_len(buf_len: usize) -> usize {
    buf_len + max_overhead(buf_len) + 1
}

/// Encodes data in-place using COBS (Consistent Overhead Byte Stuffing) algorithm.
///
/// # Algorithm Overview
/// COBS replaces all zero bytes in the input with overhead bytes that indicate
/// the distance to the next zero byte. This ensures the encoded output contains
/// no zero bytes, making it suitable for packet-based protocols.
///
/// # How it Works
/// 1. Scan through the input looking for zero bytes
/// 2. Replace each zero byte with an overhead byte (1-254, or 255 for special case)
/// 3. The overhead byte indicates how many bytes follow until the next zero
/// 4. A "virtual zero" is treated as existing at the end of the input
///
/// # Special Cases
/// - Overhead value 255: Indicates 254 non-zero bytes, another overhead follows
/// - Overhead value N (1-254): Indicates N-1 data bytes, then a zero
/// - Sequences of 254+ non-zero bytes trigger additional 255 overhead bytes
///
/// # In-Place Encoding
/// This function modifies the buffer in-place by:
/// - Rotating bytes right to make room for overhead bytes
/// - Tracking how many overhead bytes have been inserted (expands the data)
/// - Returning the new encoded length
pub fn cobs_encode_in_place(buf: &mut [u8], len: usize) -> Result<usize, Error> {
    if len == 0 {
        return Err(Error::InvalidDataLength);
    }
    if buf.len() < required_buf_len(len) {
        return Err(Error::BufferTooSmall);
    }

    // Current position in the buffer while scanning
    let mut index: usize = 0;
    // Position of the last overhead byte that needs to be updated
    let mut previous_zero_index: Option<usize> = None;
    // Counter for bytes until the next zero (includes the zero itself)
    let mut bytes_till_next_zero: u8 = 0;
    // How many overhead bytes have been inserted (buffer grows as we encode)
    let mut overhead_bytes_count: usize = 0;

    // Process all bytes plus the virtual zero at the end
    // Note: we iterate while <= because we need to process the virtual zero
    while index <= len + overhead_bytes_count {
        bytes_till_next_zero += 1;
        let is_last_iteration = index == len + overhead_bytes_count;

        // Special case: we've accumulated 254 non-zero bytes
        // COBS can only encode 254 bytes in one block, so we need to insert
        // a 255 overhead byte to signal "more non-zero bytes follow"
        if bytes_till_next_zero == 255 && !is_last_iteration {
            // Insert a 0xFF (255) overhead byte at the current position
            // This will be replaced with 255 when we encounter the next zero
            buf[index..].rotate_right(1);
            buf[index] = 0;
            overhead_bytes_count += 1;
        }

        // Get the current byte (or virtual zero at the end)
        let byte = if is_last_iteration {
            // The virtual zero at the end of input ensures the last segment gets encoded
            0
        } else {
            buf[index]
        };

        // When we encounter a zero byte (real or virtual), we need to encode
        // the distance from the previous zero (or start) to this zero
        if byte == 0 {
            match previous_zero_index {
                Some(prev_index) => {
                    // We've seen a zero before, so there's already an overhead byte
                    // placeholder at prev_index. Update it with the actual distance.
                    buf[prev_index] = bytes_till_next_zero;
                    bytes_till_next_zero = 0;
                    previous_zero_index = Some(index);
                }
                None => {
                    // This is the first zero we've encountered.
                    // We need to insert an overhead byte at the beginning of the buffer.
                    buf.rotate_right(1);
                    buf[0] = bytes_till_next_zero;
                    bytes_till_next_zero = 0;
                    overhead_bytes_count += 1;
                    // Everything shifted right by 1, so increment index to stay at same position
                    index += 1;
                    previous_zero_index = Some(index);
                }
            }
        }
        index += 1;
    }

    // Return the new encoded length (original length + inserted overhead bytes)
    Ok(len + overhead_bytes_count)
}

/// Decodes COBS-encoded data in-place, reversing the encoding process.
///
/// # Algorithm Overview
/// COBS decoding reconstructs the original data by:
/// 1. Reading overhead bytes that indicate how many data bytes follow
/// 2. Copying those bytes to the output position
/// 3. Writing a zero byte (except for special cases)
/// 4. Repeating until all encoded data is consumed
///
/// # How it Works
/// - Each overhead byte (1-254) indicates: "copy N-1 bytes, then write a zero"
/// - Overhead byte 255 is special: "copy 254 bytes, another overhead follows"
/// - Since encoding shrinks the data (removes overhead bytes), we can safely
///   read from ahead and write to earlier positions without overwriting data
///
/// # The Virtual Zero
/// During encoding, a "virtual zero" is treated as existing at the end.
/// This ensures the last segment gets encoded properly. During decoding,
/// we must detect and remove this trailing zero to match the original input.
///
/// # In-Place Decoding
/// This function modifies the buffer in-place by:
/// - Reading from the end (encoded data) and writing to the front
/// - Maintaining separate read_idx and write_idx positions
/// - write_idx is always <= read_idx, ensuring no data is overwritten
pub fn cobs_decode_in_place(buf: &mut [u8], len: usize) -> Result<usize, Error> {
    if len == 0 {
        return Err(Error::InvalidDataLength);
    }
    if buf.len() < len {
        return Err(Error::BufferTooSmall);
    }

    // Position we're reading from in the encoded stream
    let mut read_idx = 0;
    // Position we're writing to in the decoded stream
    let mut write_idx = 0;
    // Track the last overhead byte to detect virtual zero
    let mut last_overhead: Option<u8> = None;

    while read_idx < len {
        // Read the overhead byte that tells us how many data bytes follow
        let overhead = buf[read_idx];
        read_idx += 1;

        // Zero overhead bytes are invalid in COBS encoding
        if overhead == 0 {
            return Err(Error::InvalidDataLength);
        }

        // Determine how many bytes to copy based on the overhead value
        let copy_len = if overhead == 255 {
            // Special case: 255 means "254 non-zero bytes, no zero after"
            254
        } else {
            // Normal case: overhead N means "N-1 data bytes, then a zero"
            (overhead - 1) as usize
        };

        // Validate that the encoded data has enough bytes
        if read_idx + copy_len > len {
            return Err(Error::InvalidDataLength);
        }

        // Copy the data bytes from read position to write position
        for _ in 0..copy_len {
            buf[write_idx] = buf[read_idx];
            write_idx += 1;
            read_idx += 1;
        }

        // Write a zero byte after the segment (unless overhead was 255)
        // The 255 overhead indicates another overhead follows, not a zero
        if overhead != 255 {
            buf[write_idx] = 0;
            write_idx += 1;
        }

        last_overhead = Some(overhead);
    }

    // Remove the trailing zero that corresponds to the virtual zero added during encoding
    // The encoder treats the end of input as having a virtual zero to ensure the last
    // segment gets encoded. We must remove this extra zero to match the original input.
    if last_overhead == Some(1) {
        // Last overhead was 1: "0 data bytes + virtual zero"
        // We wrote an extra zero we shouldn't have, so remove it
        write_idx -= 1;
    } else if last_overhead.is_some() && last_overhead != Some(255) {
        // Last overhead was N (2-254): "(N-1) data bytes + virtual zero"
        // We wrote an extra zero after the data, remove it
        write_idx -= 1;
    }
    // If last overhead was 255, no zero was written, so nothing to remove

    Ok(write_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_buffer<const N: usize>(s: &str) -> ([u8; N], usize) {
        let mut buf = [0; N];
        let iter = s.split_whitespace();
        let mut index = 0;
        let mut previous_number = 0;
        let mut should_generate_sequence = false;

        for w in iter {
            if w == ".." || w == "..." {
                should_generate_sequence = true;
            } else {
                let n: u8 = u8::from_str_radix(w, 16).unwrap();
                if should_generate_sequence {
                    for i in (previous_number + 1)..=n {
                        buf[index] = i;
                        index += 1;
                    }
                    previous_number = n;
                    should_generate_sequence = false;
                } else {
                    buf[index] = n;
                    previous_number = n;
                    index += 1;
                }
            }
        }

        (buf, index)
    }

    fn encode_test<const N: usize>(before: &str, after: &str) {
        let (mut buf, len) = generate_buffer::<N>(before);
        let (expected_buf, expected_len) = generate_buffer::<N>(after);
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, expected_len);
        assert_eq!(buf[..new_len], expected_buf[..expected_len]);
    }

    fn decode_test<const N: usize>(before: &str, after: &str) {
        let (mut buf, len) = generate_buffer::<N>(before);
        let (expected_buf, expected_len) = generate_buffer::<N>(after);
        let decode_result = cobs_decode_in_place(&mut buf, len);
        assert!(decode_result.is_ok());
        let new_len = decode_result.unwrap();
        assert_eq!(new_len, expected_len);
        assert_eq!(buf[..new_len], expected_buf[..expected_len]);
    }

    fn roundtrip_test<const N: usize>(before: &str, after: &str) {
        encode_test::<N>(before, after);
        decode_test::<N>(after, before);
    }

    #[test]
    fn roundtrip_wiki_tests() {
        roundtrip_test::<3>("00", "01 01");
        roundtrip_test::<4>("00 00", "01 01 01");
        roundtrip_test::<5>("00 11 00", "01 02 11 01");
        roundtrip_test::<6>("11 22 00 33", "03 11 22 02 33");
        roundtrip_test::<6>("11 22 33 44", "05 11 22 33 44");
        roundtrip_test::<6>("11 00 00 00", "02 11 01 01 01");
        roundtrip_test::<300>("01 02 03 ... FD FE", "FF 01 02 03 ... FD FE");
        roundtrip_test::<300>("00 01 02 ... FC FD FE", "01 FF 01 02 ... FC FD FE");
        roundtrip_test::<300>("01 02 03 ... FD FE FF", "FF 01 02 03 ... FD FE 02 FF");
        roundtrip_test::<300>("02 03 04 ... FE FF 00", "FF 02 03 04 ... FE FF 01 01");
        roundtrip_test::<300>("03 04 05 ... FF 00 01", "FE 03 04 05 ... FF 02 01");
    }

    #[test]
    fn roundtrip_example_a() {
        roundtrip_test::<10>("2F A2 00 92 73 02", "03 2F A2 04 92 73 02");
    }

    #[test]
    fn decode_error_empty_input() {
        let mut buf = [0u8; 10];
        let result = cobs_decode_in_place(&mut buf, 0);
        assert_eq!(result, Err(Error::InvalidDataLength));
    }

    #[test]
    fn decode_error_zero_overhead() {
        let mut buf = [0x00, 0x11, 0x22];
        let result = cobs_decode_in_place(&mut buf, 3);
        assert_eq!(result, Err(Error::InvalidDataLength));
    }

    #[test]
    fn decode_error_truncated_data() {
        // Overhead says 5 bytes but only 2 available
        let mut buf = [0x06, 0x11, 0x22];
        let result = cobs_decode_in_place(&mut buf, 3);
        assert_eq!(result, Err(Error::InvalidDataLength));
    }

    #[test]
    fn decode_error_buffer_too_small() {
        let mut buf = [0u8; 2];
        let result = cobs_decode_in_place(&mut buf, 5);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }

    #[test]
    fn encode_error_empty_input() {
        let mut buf = [0u8; 10];
        let result = cobs_encode_in_place(&mut buf, 0);
        assert_eq!(result, Err(Error::InvalidDataLength));
    }

    #[test]
    fn encode_error_buffer_too_small() {
        let mut buf = [0u8; 2];
        let result = cobs_encode_in_place(&mut buf, 5);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }
}
