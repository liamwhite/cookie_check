extern crate base64;
extern crate openssl;
extern crate percent_encoding;
extern crate serde_json;

use std::error::Error;
use percent_encoding::percent_decode;
use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

#[no_mangle]
pub unsafe extern "C" fn c_request_authenticated(
    key:    *const u8, keylen: usize,
    cookie: *const u8, cookielen: usize
) -> bool {
    std::panic::catch_unwind(|| {
        let u8_key    = std::slice::from_raw_parts(key, keylen);
        let u8_cookie = std::slice::from_raw_parts(cookie, cookielen);

        determine(u8_key, u8_cookie).unwrap_or(false)
    }).unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn c_derive_key(
    secret: *const u8, secretlen: usize,
    salt:   *const u8, saltlen: usize,
    key:    *mut   u8, keylen: usize
) -> () {
    std::panic::catch_unwind(|| {
        let u8_secret  = std::slice::from_raw_parts(secret, secretlen);
        let u8_salt    = std::slice::from_raw_parts(salt, saltlen);
        let mut u8_key = std::slice::from_raw_parts_mut(key, keylen);

        derive_key(u8_secret, u8_salt, u8_key).unwrap_or(())
    }).unwrap_or(())
}

// ---

fn determine(key: &[u8], cookie: &[u8]) -> Result<bool, Box<Error>> {
    let decoded    = decode_to_data_iv(&cookie)?;
    let decrypted  = decrypt_session(&key, &decoded.0, &decoded.1)?;
    let determined = user_authenticated(decrypted.as_str())?;

    Ok(determined)
}

fn decode_to_data_iv(cookie: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<Error>> {
    let url_decoded = percent_decode(&cookie).decode_utf8()?;

    // checking the signature is not important here so we just throw it out
    let parts: Vec<&str> = url_decoded.split("--").collect();
    if parts.len() != 2 {
        return Err("invalid cookie".into());
    }

    let encrypted_blob = String::from_utf8(base64::decode(parts[0])?)?;
    let encrypted_parts: Vec<&str> = encrypted_blob.split("--").collect();
    if encrypted_parts.len() != 2 {
        return Err("invalid cookie".into());
    }

    let data = base64::decode(encrypted_parts[0])?;
    let iv   = base64::decode(encrypted_parts[1])?;

    Ok((data, iv))
}

fn derive_key(secret: &[u8], salt: &[u8], key: &mut [u8]) -> Result<(), Box<Error>> {
    Ok(openssl::pkcs5::pbkdf2_hmac(secret, salt, 1000, MessageDigest::sha1(), &mut key[..])?)
}

fn decrypt_session(key: &[u8], data: &Vec<u8>, iv: &Vec<u8>) -> Result<String, Box<Error>> {
    Ok(String::from_utf8(openssl::symm::decrypt(Cipher::aes_256_cbc(), &key, Some(&iv), &data)?)?)
}

fn user_authenticated(data: &str) -> Result<bool, Box<Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    Ok(v.pointer("/warden.user.user.key/0/0").is_some())
}
