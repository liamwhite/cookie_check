extern crate base64;
extern crate chrono;
extern crate hex;
extern crate openssl;
extern crate percent_encoding;
extern crate serde_json;

use std::error::Error;
use percent_encoding::percent_decode;
use openssl::hash::MessageDigest;
use openssl::symm::Cipher;
use chrono::prelude::*;

mod types;
use types::*;

#[no_mangle]
pub unsafe extern fn c_request_authenticated(
    key:    *const KeyData<'static>,
    cookie: *const CookieData<'static>
) -> bool {
    determine(&*key, (*cookie).cookie).unwrap_or(false)
}

#[no_mangle]
pub unsafe extern fn c_derive_key(key: *mut KeyData<'static>) {
	derive_key(&mut *key).unwrap_or(())
}

// ---

fn determine<'a>(key: &KeyData<'a>, cookie: &[u8]) -> Result<bool, Box<Error>> {
    let decoded    = decode_cookie(&cookie)?;
    let decrypted  = decrypt_session(&key.key, &decoded.0, &decoded.1, &decoded.2)?;
    let determined = user_authenticated(decrypted.as_str())?;

    Ok(determined)
}

fn decode_cookie<'a>(cookie: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<Error>> {
    let url_decoded = percent_decode(&cookie).decode_utf8()?;

    let parts: Vec<&str> = url_decoded.split("--").collect();
    if parts.len() != 3 {
        return Err("invalid cookie".into());
    }

    let data     = base64::decode(parts[0])?;
    let iv       = base64::decode(parts[1])?;
    let auth_tag = base64::decode(parts[2])?;

    Ok((data, iv, auth_tag))
}

fn derive_key<'a>(key: &mut KeyData<'a>) -> Result<(), Box<Error>> {
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.salt, 1000, MessageDigest::sha1(), &mut key.key)?;
    Ok(())
}

fn decrypt_session(key: &[u8], data: &Vec<u8>, iv: &Vec<u8>, auth_tag: &Vec<u8>) -> Result<String, Box<Error>> {
    Ok(String::from_utf8(openssl::symm::decrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), &[], &data, &auth_tag)?)?)
}

fn user_authenticated(data: &str) -> Result<bool, Box<Error>> {
    let v_outer: serde_json::Value = serde_json::from_str(data)?;

    let (message, expiry) = match (v_outer.pointer("/_rails/message"), v_outer.pointer("/_rails/pur"), v_outer.pointer("/_rails/exp")) {
        (Some(serde_json::Value::String(message)), Some(serde_json::Value::Null), Some(serde_json::Value::String(expiry))) =>
            (message, expiry),
        _ =>
            return Err("invalid cookie".into())
    };

    let utc_expiry = DateTime::parse_from_rfc3339(expiry)?;
    if utc_expiry.with_timezone(&Utc) <= Utc::now() {
        return Err("invalid cookie".into());
    }

    let raw_message = base64::decode(message)?;
    let str_message = std::str::from_utf8(&raw_message)?;
    let v_inner: serde_json::Value = serde_json::from_str(str_message)?;

    Ok(v_inner.pointer("/warden.user.user.key/0/0").is_some())
}
