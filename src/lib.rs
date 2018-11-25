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
    let decoded    = decode_to_data_iv(&key, &cookie)?;
    let decrypted  = decrypt_session(&key.key, &decoded.0, &decoded.1)?;
    let determined = user_authenticated(decrypted.as_str())?;

    Ok(determined)
}

fn decode_to_data_iv<'a>(key: &KeyData<'a>, cookie: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<Error>> {
    let url_decoded = percent_decode(&cookie).decode_utf8()?;

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

fn derive_key<'a>(key: &mut KeyData<'a>) -> Result<(), Box<Error>> {
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.salt, 1000, MessageDigest::sha1(), &mut key.key)?;
    openssl::pkcs5::pbkdf2_hmac(key.secret, key.sign_salt, 1000, MessageDigest::sha1(), &mut key.sign_key)?;
    Ok(())
}

fn validate_hmac<'a>(key: &KeyData<'a>, parts: &Vec<&str>) -> Result<bool, Box<Error>> {
    let pkey = PKey::hmac(&key.sign_key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(parts[0].as_bytes())?;

    let hmac_computed = signer.sign_to_vec()?;
    let hmac_known    = hex::decode(parts[1])?;

    if hmac_computed.len() == hmac_known.len() {
        Ok(openssl::memcmp::eq(&hmac_computed, &hmac_known))
    } else {
        Err("invalid cookie".into())
    }
}

fn decrypt_session(key: &[u8], data: &Vec<u8>, iv: &Vec<u8>) -> Result<String, Box<Error>> {
    Ok(String::from_utf8(openssl::symm::decrypt(Cipher::aes_256_cbc(), &key, Some(&iv), &data)?)?)
}

fn user_authenticated(data: &str) -> Result<bool, Box<Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    Ok(v.pointer("/warden.user.user.key/0/0").is_some())
}
