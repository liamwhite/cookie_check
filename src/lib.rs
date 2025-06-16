extern crate base64;
extern crate ring;

use std::convert::TryInto;
use std::error::Error;
use std::str;

mod types;
mod xchacha;
use ring::{aead, pbkdf2};
use std::num::NonZeroU32;
use types::*;
use xchacha::xchacha20;

const PHOENIX_AAD: [u8; 7] = *b"A128GCM";
const PLUG_CRYPTO: &'static str = "XCP";
const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_request_authenticated(
    key: *const KeyData<'static>,
    cookie: *const CookieData<'static>,
) -> i32 {
    unsafe { determine(&*key, (*cookie).cookie).unwrap_or(false) as i32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_ip_authenticated(
    key: *const KeyData<'static>,
    cookie: *const CookieData<'static>,
    ip: *const IpData<'static>,
) -> i32 {
    unsafe { determine_ip(&*key, (*cookie).cookie, (*ip).ip).unwrap_or(false) as i32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_derive_key(key: *mut KeyData<'static>) {
    unsafe { derive_key(&mut *key).unwrap_or(()) }
}

// ---

fn determine<'a>(key: &KeyData<'a>, cookie: &[u8]) -> Result<bool, Box<dyn Error>> {
    let decoded = decode_cookie(&cookie)?;
    let decrypted = decrypt_session(decoded, &PHOENIX_AAD, &key.key)?;
    let determined = session_important(&decrypted);

    Ok(determined)
}

fn determine_ip<'a>(key: &KeyData<'a>, cookie: &[u8], ip: &[u8]) -> Result<bool, Box<dyn Error>> {
    let decoded = decode_cookie(&cookie)?;
    let decrypted = decrypt_session(decoded, &PHOENIX_AAD, &key.key)?;
    let important = session_important(&decrypted);
    let determined = important && contains_ip(&decrypted, ip);

    Ok(determined)
}

fn decode_cookie(cookie: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = str::from_utf8(cookie)?;
    let parts: Vec<&str> = decoded.split(".").collect();

    if parts.len() != 2 || !parts[0].eq(PLUG_CRYPTO) {
        return Err("invalid cookie".into());
    }

    Ok(base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)?)
}

fn decrypt_session(
    iv_cipher_tag_cipher_text: Vec<u8>,
    aad: &[u8],
    secret: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if iv_cipher_tag_cipher_text.len() < 40 {
        return Err("invalid cipher part".into());
    }

    let iv = &iv_cipher_tag_cipher_text[0..24];
    let cipher_tag = &iv_cipher_tag_cipher_text[24..40];
    let cipher_text = &iv_cipher_tag_cipher_text[40..];
    let (subkey, nonce) = xchacha20(secret, iv);
    let unbound_key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &subkey).map_err(|_| "invalid key")?;
    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);

    let mut in_out = cipher_text.to_vec();

    less_safe_key
        .open_in_place_separate_tag(
            nonce,
            aead::Aad::from(aad),
            cipher_tag.try_into().unwrap(),
            &mut in_out,
            0..,
        )
        .map_err(|_| "decryption failed")?;

    Ok(in_out)
}

fn derive_key<'a>(key: &mut KeyData<'a>) -> Result<(), Box<dyn Error>> {
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        KEY_ITERATIONS,
        key.salt,
        key.secret,
        &mut key.key,
    );

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        KEY_ITERATIONS,
        key.sign_salt,
        key.secret,
        &mut key.sign_key,
    );

    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn session_important(session_data: &Vec<u8>) -> bool {
    find_subsequence(session_data, b"user_token").is_some()
}

fn contains_ip(session_data: &Vec<u8>, ip: &[u8]) -> bool {
    find_subsequence(session_data, ip).is_some()
}
