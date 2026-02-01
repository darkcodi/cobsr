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
                    buf[0..].rotate_right(1);
                    buf[0] = bytes_till_next_zero;
                    bytes_till_next_zero = 0;
                    overhead_bytes_count += 1;
                    index += 1; // we moved everything 1 byte right, so we have to increment it to point to the same position
                    previous_zero_index = Some(index);
                }
            }
        } else if bytes_till_next_zero == 255 {
            // we have a group of 254 non-zero bytes in a row, insert extra 00 at this index
            buf[index..].rotate_right(1);
            buf[index] = 0;
            overhead_bytes_count += 1;
            // we'll reprocess this position again
            bytes_till_next_zero -= 1;
            index -= 1;
        }
        index += 1;
    }

    Ok(len + overhead_bytes_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_wiki1() {
        let mut buf = [0x00, 0x00, 0x00];
        let len = 1;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 2);
        assert_eq!(buf[..new_len], [0x01, 0x01]);
    }

    #[test]
    fn encode_wiki2() {
        let mut buf = [0x00, 0x00, 0x00, 0x00];
        let len = 2;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 3);
        assert_eq!(buf[..new_len], [0x01, 0x01, 0x01]);
    }

    #[test]
    fn encode_wiki3() {
        let mut buf = [0x00, 0x11, 0x00, 0x00, 0x00];
        let len = 3;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 4);
        assert_eq!(buf[..new_len], [0x01, 0x02, 0x11, 0x01]);
    }

    #[test]
    fn encode_wiki4() {
        let mut buf = [0x11, 0x22, 0x00, 0x33, 0x00, 0x00];
        let len = 4;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 5);
        assert_eq!(buf[..new_len], [0x03, 0x11, 0x22, 0x02, 0x33]);
    }

    #[test]
    fn encode_wiki5() {
        let mut buf = [0x11, 0x22, 0x33, 0x44, 0x00, 0x00];
        let len = 4;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 5);
        assert_eq!(buf[..new_len], [0x05, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn encode_wiki6() {
        let mut buf = [0x11, 0x00, 0x00, 0x00, 0x00, 0x00];
        let len = 4;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 5);
        assert_eq!(buf[..new_len], [0x02, 0x11, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn encode_wiki7() {
        let mut buf = [0; 300];
        for i in 0x01..=0xFE {
            buf[i - 1] = i as u8;
        }
        let len = 254;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 255);
        assert_eq!(buf[0], 0xFF);
        for i in 0x01..=0xFE {
            assert_eq!(buf[i], i as u8);
        }
    }

    #[test]
    fn encode_wiki8() {
        let mut buf = [0; 300];
        for i in 0x00..=0xFE {
            buf[i] = i as u8;
        }
        let len = 255;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 256);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0xFF);
        for i in 0x01..=0xFE {
            assert_eq!(buf[i + 1], i as u8);
        }
    }

    #[test]
    fn encode_wiki9() {
        let mut buf = [0; 300];
        for i in 0x01..=0xFF {
            buf[i - 1] = i as u8;
        }
        let len = 255;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 257);
        assert_eq!(buf[0], 0xFF);
        for i in 0x01..=0xFE {
            assert_eq!(buf[i], i as u8);
        }
        assert_eq!(buf[255], 0x02);
        assert_eq!(buf[256], 0xFF);
    }

    #[test]
    fn encode_wiki10() {
        let mut buf = [0; 300];
        for i in 0x02..=0xFF {
            buf[i - 2] = i as u8;
        }
        buf[254] = 0x00;
        eprintln!("BUF BEFORE: {:?}", &buf);
        let len = 255;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        eprintln!("BUF AFTER: {:?}", &buf);
        assert_eq!(new_len, 257);
        assert_eq!(buf[0], 0xFF);
        for i in 0x02..=0xFF {
            assert_eq!(buf[i - 1], i as u8);
        }
        assert_eq!(buf[255], 0x01);
        assert_eq!(buf[256], 0x01);
    }

    #[test]
    fn encode_example_a() {
        let mut buf = [0x2F, 0xA2, 0x00, 0x92, 0x73, 0x02, 0x00, 0x00, 0x00];
        let len = 6;
        let encode_result = cobs_encode_in_place(&mut buf, len);
        assert!(encode_result.is_ok());
        let new_len = encode_result.unwrap();
        assert_eq!(new_len, 7);
        assert_eq!(buf[..new_len], [0x03, 0x2F, 0xA2, 0x04, 0x92, 0x73, 0x02]);
    }
}
