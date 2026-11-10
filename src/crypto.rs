// NetFreedom - open, local, reversible access to the open Internet.
// Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX>
// Project home: https://github.com/PsyGioX/NetFreedom
//
// SPDX-License-Identifier: GPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

//! The few cryptographic primitives the native engine needs to read the SNI out of a QUIC Initial
//! packet: SHA-256, HMAC, HKDF, AES-128 (encryption direction only) and AES-128-GCM decryption.
//! Written without dependencies and checked against the published test vectors (see the tests).
//!
//! These are for *reading packets the sender protected with a key anyone can derive*; nothing here
//! protects a secret, so there is no constant-time machinery beyond comparing the tag in one pass.

// ------------------------------------------------------------------------------ SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand with SHA-256; `len` up to 255 * 32 bytes.
pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(i);
        t = hmac_sha256(prk, &m).to_vec();
        out.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

// ------------------------------------------------------------------------------ AES-128

const fn gen_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        // p *= 3, q /= 3 in GF(2^8); p and q stay multiplicative inverses of each other
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
}

static SBOX: [u8; 256] = gen_sbox();

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1B } else { 0 }
}

pub struct Aes128 {
    rk: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Aes128 {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for (r, k) in rk.iter_mut().enumerate() {
            for c in 0..4 {
                k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        Aes128 { rk }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        let add = |s: &mut [u8; 16], r: usize| s.iter_mut().zip(self.rk[r]).for_each(|(a, b)| *a ^= b);
        add(&mut s, 0);
        for r in 1..=10 {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let o = s;
            for c in 0..4 {
                for row in 0..4 {
                    s[4 * c + row] = o[4 * ((c + row) % 4) + row];
                }
            }
            if r != 10 {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    let t = a[0] ^ a[1] ^ a[2] ^ a[3];
                    s[4 * c] = a[0] ^ t ^ xtime(a[0] ^ a[1]);
                    s[4 * c + 1] = a[1] ^ t ^ xtime(a[1] ^ a[2]);
                    s[4 * c + 2] = a[2] ^ t ^ xtime(a[2] ^ a[3]);
                    s[4 * c + 3] = a[3] ^ t ^ xtime(a[3] ^ a[0]);
                }
            }
            add(&mut s, r);
        }
        s
    }
}

// ------------------------------------------------------------------------------ AES-128-GCM

fn gmul(x: u128, h: u128) -> u128 {
    let (mut z, mut v) = (0u128, h);
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ (0xE1u128 << 120) } else { v >> 1 };
    }
    z
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    for part in [aad, ct] {
        for chunk in part.chunks(16) {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            y = gmul(y ^ u128::from_be_bytes(b), h);
        }
    }
    let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    gmul(y ^ lens, h)
}

/// Decrypts `ct_and_tag` (ciphertext followed by the 16-byte tag). `None` if the tag is wrong.
pub fn aes128_gcm_decrypt(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let aes = Aes128::new(key);
    let h = u128::from_be_bytes(aes.encrypt_block(&[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let expect = ghash(h, aad, ct) ^ u128::from_be_bytes(aes.encrypt_block(&j0));
    let diff = expect.to_be_bytes().iter().zip(tag).fold(0u8, |a, (x, y)| a | (x ^ y));
    if diff != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(ct.len());
    let mut ctr = u32::from_be_bytes([j0[12], j0[13], j0[14], j0[15]]);
    for chunk in ct.chunks(16) {
        ctr = ctr.wrapping_add(1);
        let mut cb = j0;
        cb[12..].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes.encrypt_block(&cb);
        out.extend(chunk.iter().zip(ks).map(|(c, k)| c ^ k));
    }
    Some(out)
}

/// The encryption direction, used only by tests to build packets.
#[cfg(test)]
pub fn aes128_gcm_encrypt(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key);
    let h = u128::from_be_bytes(aes.encrypt_block(&[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut ct = Vec::new();
    let mut ctr = 1u32;
    for chunk in pt.chunks(16) {
        ctr = ctr.wrapping_add(1);
        let mut cb = j0;
        cb[12..].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes.encrypt_block(&cb);
        ct.extend(chunk.iter().zip(ks).map(|(p, k)| p ^ k));
    }
    let tag = ghash(h, aad, &ct) ^ u128::from_be_bytes(aes.encrypt_block(&j0));
    ct.extend_from_slice(&tag.to_be_bytes());
    ct
}

#[cfg(test)]
pub(crate) fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_standard_vectors() {
        assert_eq!(sha256(b"abc").to_vec(), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert_eq!(sha256(b"").to_vec(), hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(sha256(long).to_vec(), hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    }

    #[test]
    fn hmac_and_hkdf_match_rfc_vectors() {
        // RFC 4231 test case 1
        assert_eq!(hmac_sha256(&[0x0b; 20], b"Hi There").to_vec(), hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        // RFC 4231 test case 6: a key longer than the block size
        assert_eq!(
            hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First").to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
        // RFC 5869 test case 1
        let prk = hkdf_extract(&hex("000102030405060708090a0b0c"), &[0x0b; 22]);
        assert_eq!(prk.to_vec(), hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        let okm = hkdf_expand(&prk, &hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        assert_eq!(okm, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    #[test]
    fn aes128_matches_fips_197() {
        let k: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let p: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        assert_eq!(Aes128::new(&k).encrypt_block(&p).to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        // Appendix B
        let k: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let p: [u8; 16] = hex("3243f6a8885a308d313198a2e0370734").try_into().unwrap();
        assert_eq!(Aes128::new(&k).encrypt_block(&p).to_vec(), hex("3925841d02dc09fbdc118597196a0b32"));
    }

    #[test]
    fn gcm_matches_the_nist_test_cases() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        // test case 1: empty plaintext
        assert_eq!(aes128_gcm_decrypt(&key, &iv, &[], &hex("58e2fccefa7e3061367f1d57a4e7455a")).unwrap(), Vec::<u8>::new());
        // test case 2
        let ct = hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        assert_eq!(aes128_gcm_decrypt(&key, &iv, &[], &ct).unwrap(), vec![0u8; 16]);
        // test case 4 (with AAD, partial last block)
        let key: [u8; 16] = hex("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
        let iv: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct = hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
        let tag = hex("5bc94fbc3221a5db94fae95ae7121a47");
        let mut ct_tag = ct.clone();
        ct_tag.extend_from_slice(&tag);
        assert_eq!(aes128_gcm_decrypt(&key, &iv, &aad, &ct_tag).unwrap(), pt);
        assert_eq!(aes128_gcm_encrypt(&key, &iv, &aad, &pt), ct_tag);
        // a flipped bit anywhere is rejected
        ct_tag[3] ^= 1;
        assert!(aes128_gcm_decrypt(&key, &iv, &aad, &ct_tag).is_none());
    }
}
