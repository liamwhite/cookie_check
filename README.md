# cookie_check

Checking authentication of Rails 6 sessions through a C API, via safe Rust. Does not panic back into C. Requires openssl.

## Parameters

```rb
secret = Rails.application.config.secret_key_base
salt   = Rails.application.config.action_dispatch.authenticated_encrypted_cookie_salt
```

## Example usage

```c
// gcc cookie_test.c -o cookie_test -L. -lcookie_check -lssl -lcrypto -ldl -lpthread
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct c_key_data {
    const uint8_t *secret;
    size_t secretlen;
    const uint8_t *salt;
    size_t saltlen;
    uint8_t key[32];
} c_key_data;

typedef struct c_cookie_data {
    const uint8_t *cookie;
    size_t cookielen;
} c_cookie_data;

int c_request_authenticated(c_key_data const *key, c_cookie_data const *cookie);
void c_derive_key(c_key_data *key);

int main(int argc, char *argv[])
{
    c_key_data key;
    c_cookie_data cookie;

    key.secret    = argv[1];
    key.salt      = argv[2];
    key.secretlen = strlen(key.secret);
    key.saltlen   = strlen(key.salt);

    c_derive_key(&key);

    cookie.cookie = argv[3];
    cookie.cookielen = strlen(cookie.cookie);

    if (c_request_authenticated(&key, &cookie))
        puts("Authenticated");
    else
        puts("Not authenticated");

    return 0;
}
```

## Performance

Checking takes on average 0.00582ms on an Intel i7-4790K CPU. This average checking time represents the best-case performance scenario, where `c_request_authenticated` is called repeatedly in a tight loop, and data and instruction caches are filled. Performance in real workloads will likely vary.
