#[repr(C)]
pub struct KeyData<'a> {
    pub secret:    &'a [u8],
    pub salt:      &'a [u8],
    pub sign_salt: &'a [u8],
    pub key:       [u8; 32],
    pub sign_key:  [u8; 64]
}

#[repr(C)]
pub struct CookieData<'a> {
    pub cookie: &'a [u8]
}
