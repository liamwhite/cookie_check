#[repr(C)]
pub struct c_key_data {
    pub secret:       *const u8,
    pub secretlen:    usize,
    pub salt:         *const u8,
    pub saltlen:      usize,
    pub sign_salt:    *const u8,
    pub sign_saltlen: usize,
    pub key:          [u8; 32],
    pub sign_key:     [u8; 32]
}

#[repr(C)]
pub struct c_cookie_data {
    pub cookie:    *const u8,
    pub cookielen: usize
}

pub struct KeyData<'a> {
    pub secret:    &'a [u8],
    pub salt:      &'a [u8],
    pub sign_salt: &'a [u8],
    pub key:       &'a mut [u8],
    pub sign_key:  &'a mut [u8]
}

pub struct CookieData<'a> {
    pub cookie: &'a [u8]
}

pub unsafe fn key_data_from_c<'a>(ptr: *mut c_key_data) -> KeyData<'a> {
    let ref_key: &c_key_data = &*ptr;

    let secret    = std::slice::from_raw_parts(ref_key.secret, ref_key.secretlen);
    let salt      = std::slice::from_raw_parts(ref_key.salt, ref_key.saltlen);
    let sign_salt = std::slice::from_raw_parts(ref_key.sign_salt, ref_key.sign_saltlen);

    KeyData { secret, salt, sign_salt, key: &mut (*ptr).key, sign_key: &mut (*ptr).sign_key }
}

pub unsafe fn cookie_data_from_c<'a>(ptr: *const c_cookie_data) -> CookieData<'a> {
    let ref_cookie: &c_cookie_data = &*ptr;
    let cookie = std::slice::from_raw_parts(ref_cookie.cookie, ref_cookie.cookielen);

    CookieData { cookie }
}
