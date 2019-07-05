#[repr(C)]
pub struct KeyData<'a> {
    pub secret:    &'a [u8],
    pub salt:      &'a [u8],
    pub key:       [u8; 32],
}

#[repr(C)]
pub struct CookieData<'a> {
    pub cookie: &'a [u8]
}
