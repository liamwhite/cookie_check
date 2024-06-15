// XChaCha20 is not a standard algorithm and not available in OpenSSL. Reference code:
// https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.24.0:chacha20/chacha_generic.go;l=352

const INIT: [u32; 4] = [
    0x61707865, // expa
    0x3320646e, // nd 3
    0x79622d32, // 2-by
    0x6b206574, // te k
];

/// This is a `[u8]` slice with exactly 32 elements
pub type XChaChaKey = [u8];
/// This is a `[u8]` slice with exactly 24 elements
pub type XChaChaNonce = [u8];

pub type ChaChaKey = [u8; 32];
pub type ChaChaNonce = [u8; 12];

pub fn xchacha20(key: &XChaChaKey, nonce: &XChaChaNonce) -> (ChaChaKey, ChaChaNonce) {
    let subkey = hchacha20(key, &nonce[0..16]);

    let mut subnonce = [0u8; 12];
    subnonce[4..12].copy_from_slice(&nonce[16..24]);

    (subkey, subnonce)
}

/// This is a `[u8]` slice with exactly 32 elements
type HChaChaKey = [u8];
/// This is a `[u8]` slice with exactly 16 elements
type HChaChaNonce = [u8];

fn hchacha20(key: &HChaChaKey, nonce: &HChaChaNonce) -> ChaChaKey {
    let mut x0 = INIT[0];
    let mut x1 = INIT[1];
    let mut x2 = INIT[2];
    let mut x3 = INIT[3];
    let mut x4 = to_le32(&key[0..4]);
    let mut x5 = to_le32(&key[4..8]);
    let mut x6 = to_le32(&key[8..12]);
    let mut x7 = to_le32(&key[12..16]);
    let mut x8 = to_le32(&key[16..20]);
    let mut x9 = to_le32(&key[20..24]);
    let mut x10 = to_le32(&key[24..28]);
    let mut x11 = to_le32(&key[28..32]);
    let mut x12 = to_le32(&nonce[0..4]);
    let mut x13 = to_le32(&nonce[4..8]);
    let mut x14 = to_le32(&nonce[8..12]);
    let mut x15 = to_le32(&nonce[12..16]);

    for _ in 0..10 {
        // Diagonal round.
        (x0, x4, x8, x12) = qr(x0, x4, x8, x12);
        (x1, x5, x9, x13) = qr(x1, x5, x9, x13);
        (x2, x6, x10, x14) = qr(x2, x6, x10, x14);
        (x3, x7, x11, x15) = qr(x3, x7, x11, x15);

        // Column round.
        (x0, x5, x10, x15) = qr(x0, x5, x10, x15);
        (x1, x6, x11, x12) = qr(x1, x6, x11, x12);
        (x2, x7, x8, x13) = qr(x2, x7, x8, x13);
        (x3, x4, x9, x14) = qr(x3, x4, x9, x14);
    }

    let mut out = [0u8; 32];
    from_le32(&mut out[0..4], x0);
    from_le32(&mut out[4..8], x1);
    from_le32(&mut out[8..12], x2);
    from_le32(&mut out[12..16], x3);
    from_le32(&mut out[16..20], x12);
    from_le32(&mut out[20..24], x13);
    from_le32(&mut out[24..28], x14);
    from_le32(&mut out[28..32], x15);
    out
}

fn to_le32(v: &[u8]) -> u32 {
    (v[0] as u32) + ((v[1] as u32) << 8) + ((v[2] as u32) << 16) + ((v[3] as u32) << 24)
}

fn from_le32(out: &mut [u8], v: u32) {
    out[0] = (v & 0xff) as u8;
    out[1] = ((v >> 8) & 0xff) as u8;
    out[2] = ((v >> 16) & 0xff) as u8;
    out[3] = ((v >> 24) & 0xff) as u8;
}

fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    (a, b, c, d)
}
