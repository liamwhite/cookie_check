# cookie_check

Checking authentication of Rails sessions through a C API, via safe Rust. Verifies the signature of the cookie before decoding it. Does not panic back into C. Requires openssl.

## Parameters

secret: `Rails.application.config.secret_key_base`

salt: `Rails.application.config.action_dispatch.encrypted_cookie_salt`

## Example usage

```c
// gcc cookie_test.c -o cookie_test -L. -lcookie_check -lssl -lcrypto -ldl -lpthread
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct c_key_data {
    uint8_t *secret;
    size_t  secretlen;
    uint8_t *salt;
    size_t  saltlen;
    uint8_t *sign_salt;
    size_t  sign_saltlen;
    uint8_t key[32];
    uint8_t sign_key[32];
} c_key_data;

typedef struct c_cookie_data {
    uint8_t *cookie;
    size_t  cookielen;
} c_cookie_data;

int c_request_authenticated(c_key_data *key, c_cookie_data const *cookie);
void c_derive_key(c_key_data *key);

int main(int argc, char *argv[])
{
    struct timespec start, finish;
    c_key_data key;
    c_cookie_data cookie;
    int val;

    key.secret    = argv[1];
    key.salt      = argv[2];
    key.sign_salt = argv[3];

    key.secretlen    = strlen(key.secret);
    key.saltlen      = strlen(key.salt);
    key.sign_saltlen = strlen(key.sign_salt);

    cookie.cookie = argv[4];
    cookie.cookielen = strlen(cookie.cookie);

    if (c_request_authenticated(&key, &cookie))
        puts("Authenticated");
    else
        puts("Not authenticated");

    return 0;
}
```

## Performance

Checking takes on average 0.00497ms.
