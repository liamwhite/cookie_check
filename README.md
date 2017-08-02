# cookie_check

Checking authentication of Rails sessions through a C API, via safe Rust. Does not verify the signature of the cookie before decoding it. Does not panic back into C. Requires openssl.

**Don't use this (yet)! It doesn't check the signature of the session and is susceptible to a padding oracle.**

## Parameters

secret: `Rails.application.config.secret_key_base`

salt: `Rails.application.config.action_dispatch.encrypted_cookie_salt`

## Example usage

```c
#include <stdio.h>
#include <string.h>

int c_request_authenticated(
    const char *key,
    size_t keylen,
    const char *cookie,
    size_t cookielen
);

void c_derive_key(
    const char *secret,
    size_t secretlen,
    const char *salt,
    size_t saltlen,
    char /*mut*/ key[32],
    size_t keylen
);

int main(int argc, char *argv[])
{
    const char *secret = argv[1];
    size_t secretlen = strlen(secret);

    const char *salt = argv[2];
    size_t saltlen = strlen(salt);

    const char *cookie = argv[3];
    size_t cookielen = strlen(cookie);

    char key[32] = { 0 };
    c_derive_key(secret, secretlen, salt, saltlen, key, 32);

    int val = c_request_authenticated(key, 32, cookie, cookielen);
    printf("Authenticated? %s\n", val ? "yes" : "no");

    return 0;
}
```

## Performance

Checking takes on average 0.00331ms.
