# 📦 cobsin

[![crates.io](https://img.shields.io/crates/v/cobsin)](https://crates.io/crates/cobsin)
[![docs.rs](https://img.shields.io/docsrs/cobsin)](https://docs.rs/cobsin)
[![MIT License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> COBS encoding/decoding, in-place. `no_std`, zero allocations.

**COBS** (Consistent Overhead Byte Stuffing) eliminates zero bytes from data — perfect for packet protocols where `0x00` marks boundaries.

## ✨ Why?

- 🔧 **In-place** — encode/decode without extra buffers
- 📦 **`no_std`** — works on bare-metal & embedded
- 🚀 **Zero alloc** — no heap, ever
- 📭 **Zero deps** — no external dependencies

## 🚀 Quick look

```rust
let mut buf = [0u8; 32];
buf[..11].copy_from_slice(b"Hello\x00World");

// Encode
let enc_len = cobsin::cobs_encode_in_place(&mut buf, 11)?;

// Decode
let dec_len = cobsin::cobs_decode_in_place(&mut buf, enc_len)?;

assert_eq!(&buf[..dec_len], b"Hello\x00World");
```

## 📦 Install

```toml
[dependencies]
cobsin = "0.1"
```

---

**MIT** — do whatever.
