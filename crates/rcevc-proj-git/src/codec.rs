//! SHA-1 and zlib on `std` alone.
//!
//! Git's object ids are SHA-1 (SHA-256 repositories exist but are rare);
//! objects are zlib streams. Writing uses stored (uncompressed) deflate
//! blocks, which every zlib reader accepts. Reading implements full inflate
//! (stored, fixed and dynamic Huffman blocks, RFC 1950/1951) because Git
//! itself writes compressed objects. In a networked build, `gix` replaces
//! this module.

/// SHA-1 of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut w = [0u32; 80];
    for block in msg.chunks_exact(64) {
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Adler-32 checksum.
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// zlib stream of stored deflate blocks.
pub fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 11);
    out.extend_from_slice(&[0x78, 0x01]);
    if data.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let n = data.len().div_ceil(65535);
        for (i, c) in data.chunks(65535).enumerate() {
            out.push(u8::from(i + 1 == n));
            let len = c.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(c);
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl Bits<'_> {
    fn bits(&mut self, n: u32) -> Result<u32, String> {
        while self.cnt < n {
            let &byte = self.data.get(self.pos).ok_or("deflate: unexpected end")?;
            self.buf |= (byte as u32) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
        let v = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }
}

struct Huff {
    count: [i32; 16],
    symbol: Vec<i32>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Result<Huff, String> {
        let mut count = [0i32; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        let mut left = 1i32;
        for c in count.iter().skip(1) {
            left = (left << 1) - c;
            if left < 0 {
                return Err("deflate: over-subscribed code".into());
            }
        }
        let mut offs = [0i32; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0i32; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = sym as i32;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { count, symbol })
    }

    fn decode(&self, s: &mut Bits<'_>) -> Result<i32, String> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= s.bits(1)? as i32;
            let count = self.count[len];
            if code - count < first {
                return Ok(self.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("deflate: bad code".into())
    }
}

const LBASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
    6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

#[allow(clippy::comparison_chain)] // symbol classes are literal, end, then length
fn codes(s: &mut Bits<'_>, out: &mut Vec<u8>, lit: &Huff, dist: &Huff) -> Result<(), String> {
    loop {
        let sym = lit.decode(s)?;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else {
            let sym = (sym - 257) as usize;
            if sym >= 29 {
                return Err("deflate: bad length symbol".into());
            }
            let len = LBASE[sym] as usize + s.bits(LEXT[sym] as u32)? as usize;
            let d = dist.decode(s)? as usize;
            if d >= 30 {
                return Err("deflate: bad distance symbol".into());
            }
            let dist = DBASE[d] as usize + s.bits(DEXT[d] as u32)? as usize;
            if dist > out.len() {
                return Err("deflate: distance too far".into());
            }
            for _ in 0..len {
                out.push(out[out.len() - dist]);
            }
        }
    }
}

/// Decompress a zlib stream (verifies the Adler-32 trailer).
pub fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 6 || data[0] & 0x0f != 8 || u16::from_be_bytes([data[0], data[1]]) % 31 != 0 || data[1] & 0x20 != 0 {
        return Err("zlib: bad header".into());
    }
    let mut s = Bits { data: &data[2..], pos: 0, buf: 0, cnt: 0 };
    let mut out = Vec::new();
    loop {
        let last = s.bits(1)?;
        match s.bits(2)? {
            0 => {
                s.buf = 0;
                s.cnt = 0;
                let p = s.pos;
                let hdr = s.data.get(p..p + 4).ok_or("deflate: short stored header")?;
                let len = u16::from_le_bytes([hdr[0], hdr[1]]);
                let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
                if len != !nlen {
                    return Err("deflate: stored length mismatch".into());
                }
                let body = s.data.get(p + 4..p + 4 + len as usize).ok_or("deflate: short stored block")?;
                out.extend_from_slice(body);
                s.pos = p + 4 + len as usize;
            }
            1 => {
                let mut l = [0u8; 288];
                l[..144].fill(8);
                l[144..256].fill(9);
                l[256..280].fill(7);
                l[280..].fill(8);
                let (lit, dist) = (Huff::new(&l)?, Huff::new(&[5u8; 30])?);
                codes(&mut s, &mut out, &lit, &dist)?;
            }
            2 => {
                let nlen = s.bits(5)? as usize + 257;
                let ndist = s.bits(5)? as usize + 1;
                let ncode = s.bits(4)? as usize + 4;
                if nlen > 286 || ndist > 30 {
                    return Err("deflate: bad counts".into());
                }
                let mut lengths = [0u8; 320];
                for &o in ORDER.iter().take(ncode) {
                    lengths[o] = s.bits(3)? as u8;
                }
                let lencode = Huff::new(&lengths[..19])?;
                let mut lengths = [0u8; 320];
                let mut i = 0;
                while i < nlen + ndist {
                    let sym = lencode.decode(&mut s)?;
                    if sym < 16 {
                        lengths[i] = sym as u8;
                        i += 1;
                        continue;
                    }
                    let (val, rep) = match sym {
                        16 => {
                            if i == 0 {
                                return Err("deflate: repeat with no previous".into());
                            }
                            (lengths[i - 1], 3 + s.bits(2)? as usize)
                        }
                        17 => (0, 3 + s.bits(3)? as usize),
                        _ => (0, 11 + s.bits(7)? as usize),
                    };
                    if i + rep > nlen + ndist {
                        return Err("deflate: too many lengths".into());
                    }
                    lengths[i..i + rep].fill(val);
                    i += rep;
                }
                if lengths[256] == 0 {
                    return Err("deflate: no end code".into());
                }
                let lit = Huff::new(&lengths[..nlen])?;
                let dist = Huff::new(&lengths[nlen..nlen + ndist])?;
                codes(&mut s, &mut out, &lit, &dist)?;
            }
            _ => return Err("deflate: bad block type".into()),
        }
        if last == 1 {
            break;
        }
    }
    let at = 2 + s.pos - (s.cnt / 8) as usize;
    let tail = data.get(at..at + 4).ok_or("zlib: missing checksum")?;
    if u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) != adler32(&out) {
        return Err("zlib: checksum mismatch".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::format_collect)]
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // git hash-object of an empty blob
        assert_eq!(hex(&sha1(b"blob 0\0")), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn store_then_inflate() {
        for n in [0usize, 1, 100, 65535, 65536, 200_000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            assert_eq!(zlib_inflate(&zlib_store(&data)).unwrap(), data, "n={n}");
        }
    }

    #[test]
    fn inflate_fixed_huffman() {
        // python3 -c "import zlib;print(zlib.compress(b'hello hello hello hello').hex())"
        let z = [
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03, 0x08, 0xb1,
        ];
        assert_eq!(zlib_inflate(&z).unwrap(), b"hello hello hello hello");
    }
}
