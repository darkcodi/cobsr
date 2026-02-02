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
}
