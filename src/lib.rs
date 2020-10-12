extern crate base64;
extern crate openssl;

use std::error::Error;
use std::str;
use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

mod types;
use types::*;

const PHOENIX_AAD: [u8; 7] = *b"A128GCM";

#[no_mangle]
pub unsafe extern fn c_request_authenticated(
    key:    *const KeyData<'static>,
    cookie: *const CookieData<'static>
) -> i32 {
    determine(&*key, (*cookie).cookie).unwrap_or(false) as i32
}

#[no_mangle]
pub unsafe extern fn c_ip_authenticated(
    key:    *const KeyData<'static>,
    cookie: *const CookieData<'static>,
    ip:     *const IpData<'static>
) -> i32 {
    determine_ip(&*key, (*cookie).cookie, (*ip).ip).unwrap_or(false) as i32
}

#[no_mangle]
pub unsafe extern fn c_derive_key(key: *mut KeyData<'static>) {
    derive_key(&mut *key).unwrap_or(())
}

// ---

fn determine<'a>(key: &KeyData<'a>, cookie: &[u8]) -> Result<bool, Box<dyn Error>> {
    let decoded    = decode_cookie(&cookie)?;
    let cek        = unwrap_cek(&key, &decoded.1)?;
    let decrypted  = decrypt_session(&cek, &decoded.0, &decoded.2, &decoded.3, &decoded.4)?;
    let determined = session_important(&decrypted);

    Ok(determined)
}

fn determine_ip<'a>(key: &KeyData<'a>, cookie: &[u8], ip: &[u8]) -> Result<bool, Box<dyn Error>> {
    let decoded    = decode_cookie(&cookie)?;
    let cek        = unwrap_cek(&key, &decoded.1)?;
    let decrypted  = decrypt_session(&cek, &decoded.0, &decoded.2, &decoded.3, &decoded.4)?;
    let important  = session_important(&decrypted);
    let determined = important && contains_ip(&decrypted, ip);

    Ok(determined)
}

fn decode_cookie<'a>(cookie: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let decoded = str::from_utf8(cookie)?;
    let parts: Vec<&str> = decoded.split(".").collect();

    if parts.len() != 5 {
        return Err("invalid cookie".into());
    }

    let aad      = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)?;
    let cek      = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)?;
    let iv       = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD)?;
    let data     = base64::decode_config(parts[3], base64::URL_SAFE_NO_PAD)?;
    let auth_tag = base64::decode_config(parts[4], base64::URL_SAFE_NO_PAD)?;

    if !aad.eq(&PHOENIX_AAD) || cek.len() != 44 || iv.len() != 12 || auth_tag.len() != 16 {
        return Err("invalid cookie".into())
    }

    Ok((aad, cek, iv, data, auth_tag))
}

fn derive_key<'a>(key: &mut KeyData<'a>) -> Result<(), Box<dyn Error>> {
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.salt, 1000, MessageDigest::sha256(), &mut key.key)?;
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.sign_salt, 1000, MessageDigest::sha256(), &mut key.sign_key)?;

    Ok(())
}

fn unwrap_cek<'a>(key: &KeyData<'a>, wrapped_cek: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher_text = &wrapped_cek[0..16];   // 128 bit data
    let cipher_tag  = &wrapped_cek[16..32];  // 128 bit AEAD tag
    let iv          = &wrapped_cek[32..44];  // 96 bit IV

    Ok(openssl::symm::decrypt_aead(Cipher::aes_256_gcm(), &key.key, Some(iv), &key.sign_key, cipher_text, cipher_tag)?)
}

fn decrypt_session(cek: &Vec<u8>, aad: &Vec<u8>, iv: &Vec<u8>, data: &Vec<u8>, auth_tag: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(openssl::symm::decrypt_aead(Cipher::aes_128_gcm(), &cek, Some(&iv), &aad, &data, &auth_tag)?)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn session_important(session_data: &Vec<u8>) -> bool {
    find_subsequence(session_data, b"user_token").is_some()
}

fn contains_ip(session_data: &Vec<u8>, ip: &[u8]) -> bool {
    find_subsequence(session_data, ip).is_some()
}
