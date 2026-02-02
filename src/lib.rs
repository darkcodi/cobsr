#![no_std]

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDataLength,
    BufferTooSmall,
}

pub fn max_overhead(buf_len: usize) -> usize {
    (buf_len + 253) / 254
}

pub fn required_buf_len(buf_len: usize) -> usize {
    buf_len + max_overhead(buf_len) + 1
}

pub fn cobs_encode_in_place(buf: &mut [u8], len: usize) -> Result<usize, Error> {
    if len == 0 {
        return Err(Error::InvalidDataLength);
    }
    if buf.len() < required_buf_len(len) {
        return Err(Error::BufferTooSmall);
    }

    let mut index: usize = 0;
    let mut previous_zero_index: Option<usize> = None;
    let mut bytes_till_next_zero: u8 = 0;
    let mut overhead_bytes_count: usize = 0;

    while index <= len + overhead_bytes_count {
        bytes_till_next_zero += 1;
        let is_last_iteration = index == len + overhead_bytes_count;
        if bytes_till_next_zero == 255 && !is_last_iteration {
            // we have a group of 254 non-zero bytes in a row, insert extra 00 at this index
            buf[index..].rotate_right(1);
            buf[index] = 0;
            overhead_bytes_count += 1;
        }
        let byte = if is_last_iteration {
            // last virtual byte is always 0
            0
        } else {
            buf[index]
        };
        if byte == 0 {
            match previous_zero_index {
                Some(prev_index) => {
                    // no need to insert overhead byte here, just update the previous zero index
                    buf[prev_index] = bytes_till_next_zero;
                    bytes_till_next_zero = 0;
                    previous_zero_index = Some(index);
                }
                None => {
                    // we have to insert overhead byte at the beginning
                    buf.rotate_right(1);
                    buf[0] = bytes_till_next_zero;
                    bytes_till_next_zero = 0;
                    overhead_bytes_count += 1;
                    index += 1; // we moved everything 1 byte right, so we have to increment it to point to the same position
                    previous_zero_index = Some(index);
                }
            }
        }
        index += 1;
    }

    Ok(len + overhead_bytes_count)
}

pub fn cobs_decode_in_place(buf: &mut [u8], len: usize) -> Result<usize, Error> {
    if len == 0 {
        return Err(Error::InvalidDataLength);
    }
    if buf.len() < len {
        return Err(Error::BufferTooSmall);
    }

    let mut read_idx = 0;
    let mut write_idx = 0;
    let mut last_overhead: Option<u8> = None;

    while read_idx < len {
        // Read overhead byte
        let overhead = buf[read_idx];
        read_idx += 1;

        // Zero overhead is invalid
        if overhead == 0 {
            return Err(Error::InvalidDataLength);
        }

        // Determine how many bytes to copy
        let copy_len = if overhead == 255 {
            254
        } else {
            (overhead - 1) as usize
        };

        // Validate we have enough data
        if read_idx + copy_len > len {
            return Err(Error::InvalidDataLength);
        }

        // Copy data bytes
        for _ in 0..copy_len {
            buf[write_idx] = buf[read_idx];
            write_idx += 1;
            read_idx += 1;
        }

        // Write zero after segment (unless overhead was 255)
        if overhead != 255 {
            buf[write_idx] = 0;
            write_idx += 1;
        }

        last_overhead = Some(overhead);
    }

    // Remove the trailing zero that corresponds to the virtual zero added during encoding
    // The last overhead byte indicates the distance to the virtual zero at the end
    if last_overhead == Some(1) {
        // Last overhead was 1, meaning "0 bytes + virtual zero", so remove the trailing zero
        write_idx -= 1;
    } else if last_overhead.is_some() && last_overhead != Some(255) {
        // Last overhead was N (where 2 <= N <= 254), meaning "(N-1) bytes + virtual zero"
        // Remove the trailing zero
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
        let mut iter = s.split_whitespace();
        let mut index = 0;
        let mut previous_number = 0;
        let mut should_generate_sequence = false;

        while let Some(w) = iter.next() {
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

    #[test]
    fn encode_wiki_tests() {
        encode_test::<3>("00", "01 01");
        encode_test::<4>("00 00", "01 01 01");
        encode_test::<5>("00 11 00", "01 02 11 01");
        encode_test::<6>("11 22 00 33", "03 11 22 02 33");
        encode_test::<6>("11 22 33 44", "05 11 22 33 44");
        encode_test::<6>("11 00 00 00", "02 11 01 01 01");
        encode_test::<300>("01 02 03 ... FD FE", "FF 01 02 03 ... FD FE");
        encode_test::<300>("00 01 02 ... FC FD FE", "01 FF 01 02 ... FC FD FE");
        encode_test::<300>("01 02 03 ... FD FE FF", "FF 01 02 03 ... FD FE 02 FF");
        encode_test::<300>("02 03 04 ... FE FF 00", "FF 02 03 04 ... FE FF 01 01");
        encode_test::<300>("03 04 05 ... FF 00 01", "FE 03 04 05 ... FF 02 01");
    }

    #[test]
    fn encode_example_a() {
        encode_test::<10>("2F A2 00 92 73 02", "03 2F A2 04 92 73 02");
    }

    fn decode_test<const N: usize>(encoded: &str, decoded: &str) {
        let (mut buf, encoded_len) = generate_buffer::<N>(encoded);
        let (expected_buf, expected_len) = generate_buffer::<N>(decoded);
        let decode_result = cobs_decode_in_place(&mut buf, encoded_len);
        assert!(decode_result.is_ok());
        let decoded_len = decode_result.unwrap();
        assert_eq!(decoded_len, expected_len);
        assert_eq!(buf[..decoded_len], expected_buf[..expected_len]);
    }

    fn roundtrip_test<const N: usize>(original: &str) {
        let (mut buf, original_len) = generate_buffer::<N>(original);
        let expected = buf[..original_len].to_vec();

        // Encode
        let encode_result = cobs_encode_in_place(&mut buf, original_len);
        assert!(encode_result.is_ok());
        let encoded_len = encode_result.unwrap();

        // Decode
        let decode_result = cobs_decode_in_place(&mut buf, encoded_len);
        assert!(decode_result.is_ok());
        let decoded_len = decode_result.unwrap();

        // Verify
        assert_eq!(decoded_len, original_len);
        assert_eq!(buf[..decoded_len], expected[..original_len]);
    }

    #[test]
    fn decode_wiki_tests() {
        decode_test::<3>("01 01", "00");
        decode_test::<4>("01 01 01", "00 00");
        decode_test::<5>("01 02 11 01", "00 11 00");
        decode_test::<6>("03 11 22 02 33", "11 22 00 33");
        decode_test::<6>("05 11 22 33 44", "11 22 33 44");
        decode_test::<6>("02 11 01 01 01", "11 00 00 00");
    }

    #[test]
    fn decode_example_a() {
        decode_test::<10>("03 2F A2 04 92 73 02", "2F A2 00 92 73 02");
    }

    #[test]
    fn roundtrip_wiki_tests() {
        roundtrip_test::<3>("00");
        roundtrip_test::<4>("00 00");
        roundtrip_test::<5>("00 11 00");
        roundtrip_test::<6>("11 22 00 33");
        roundtrip_test::<6>("11 22 33 44");
        roundtrip_test::<6>("11 00 00 00");
    }

    #[test]
    fn roundtrip_254_bytes() {
        roundtrip_test::<300>("01 02 03 ... FD FE");
    }

    #[test]
    fn roundtrip_255_bytes() {
        roundtrip_test::<300>("01 02 03 ... FD FE FF");
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
}
