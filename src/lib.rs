extern crate base64;
extern crate openssl;
extern crate percent_encoding;
extern crate serde_json;
extern crate hex;

use std::error::Error;
use percent_encoding::percent_decode;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use openssl::sign::Signer;
use openssl::memcmp;

mod types;
use types::*;

#[no_mangle]
pub unsafe extern "C" fn c_request_authenticated(
    key:    *mut   c_key_data,
    cookie: *const c_cookie_data
) -> bool
{
    std::panic::catch_unwind(|| {
        let ref_key    = key_data_from_c(key);
        let ref_cookie = cookie_data_from_c(cookie);

        determine(ref_key, ref_cookie.cookie).unwrap_or(false)
    }).unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn c_derive_key(key: *mut c_key_data) -> () {
    std::panic::catch_unwind(|| {
        derive_key(key_data_from_c(key)).unwrap_or(())
    }).unwrap_or(())
}

// ---

fn determine<'a>(key: KeyData<'a>, cookie: &[u8]) -> Result<bool, Box<Error>> {
    let decoded    = decode_to_data_iv(&key, &cookie)?;
    let decrypted  = decrypt_session(&key.key, &decoded.0, &decoded.1)?;
    let determined = user_authenticated(decrypted.as_str())?;

    Ok(determined)
}

fn decode_to_data_iv<'a>(key: &KeyData<'a>, cookie: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<Error>> {
    let url_decoded = percent_decode(&cookie).decode_utf8()?;

    // checking the signature is not important here so we just throw it out
    let parts: Vec<&str> = url_decoded.split("--").collect();
    if parts.len() != 2 {
        return Err("invalid cookie".into());
    }

    if !validate_hmac(&key, &parts)? {
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

fn derive_key<'a>(key: KeyData<'a>) -> Result<(), Box<Error>> {
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.salt, 1000, MessageDigest::sha1(), &mut key.key[..])?;
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.sign_salt, 1000, MessageDigest::sha1(), &mut key.sign_key[..])?;
    Ok(())
}

fn validate_hmac<'a>(key: &KeyData<'a>, parts: &Vec<&str>) -> Result<bool, Box<Error>> {
    let pkey = PKey::hmac(key.key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(parts[0].as_bytes())?;

    let hmac_computed = signer.sign_to_vec()?;
    let hmac_known    = hex::decode(parts[1])?;

    Ok(memcmp::eq(&hmac_computed, &hmac_known))
}

fn decrypt_session(key: &[u8], data: &Vec<u8>, iv: &Vec<u8>) -> Result<String, Box<Error>> {
    Ok(String::from_utf8(openssl::symm::decrypt(Cipher::aes_256_cbc(), &key, Some(&iv), &data)?)?)
}

fn user_authenticated(data: &str) -> Result<bool, Box<Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    Ok(v.pointer("/warden.user.user.key/0/0").is_some())
}
