use bytes::{Buf, BufMut};

use crate::{ip::IpProtocol, ipv4::Address};

const fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
pub fn data(mut data: &[u8]) -> u16 {
    let mut accum = 0;

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            accum += d.get_u16() as u32;
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        accum += data.get_u16() as u32;
    }

    // Add the last remaining odd byte, if any.
    if let Some(&value) = data.first() {
        accum += (value as u32) << 8;
    }

    propagate_carries(accum)
}

/// Combine several RFC 1071 compliant checksums.
pub fn combine(checksums: &[u16]) -> u16 {
    let mut accum: u32 = 0;
    for &word in checksums {
        accum += word as u32;
    }
    propagate_carries(accum)
}

/// Compute an IP pseudo header checksum.
pub fn pseudo_header(
    src_addr: &Address,
    dst_addr: &Address,
    next_header: IpProtocol,
    length: usize,
) -> u16 {
    let mut proto_len = [0u8; 4];
    proto_len[1] = next_header as u8;
    (&mut proto_len[2..4]).put_u16(length as u16);

    combine(&[
        data(src_addr.as_bytes()),
        data(dst_addr.as_bytes()),
        data(&proto_len[..]),
    ])
}
