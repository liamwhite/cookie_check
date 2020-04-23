# cookie_check

Checking "importantness" of encrypted Phoenix 1.4.9 cookie sessions through a C API, via safe Rust. Does not panic back into C. Requires openssl.

## Parameters

```elixir
secret    = config :myapp, MyAppWeb.EndPoint, secret_key_base: ... # your secret key
salt      = plug Plug.Session, encryption_salt: ... # your encryption salt (often "signed encrypted cookie")
sign_salt = plug Plug.Session, signing_salt: ... # your signing salt (often "signed cookie")
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
    const uint8_t *sign_salt;
    size_t sign_saltlen;
    uint8_t key[32];
    uint8_t sign_key[32];
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

    // Example secret, generated with `mix phx.gen.secret`
    key.secret       = "9V1RE6tqbwve1g+AiYZPmyw9OLyT4R7wBf2XjvDzA1YEhoZJBb989pcu8TT8TNj+";
    key.salt         = "signed encrypted cookie";
    key.sign_salt    = "signed cookie";

    key.secretlen    = strlen(key.secret);
    key.saltlen      = strlen(key.salt);
    key.sign_saltlen = strlen(key.sign_salt);

    c_derive_key(&key);

    cookie.cookie = argv[1];
    cookie.cookielen = strlen(cookie.cookie);

    if (c_request_authenticated(&key, &cookie))
        puts("Authenticated");
    else
        puts("Not authenticated");

    return 0;
}
```

## Performance

This library is thread safe, and throughput should scale linearly with the core count of the machine. Benchmark times reported below reflect single core performance, but a machine with 4 cores should theoretically be able to perform 4 times as many checks per second.

Performing 1 million tests of a valid, medium-sized session (363 bytes) on an i7-4790K CPU takes approximately 2.12 seconds, corresponding to an average check rate of 472,000 checks per second, or an average check time of 0.00212 milliseconds (2 microseconds).

Performing 1 million tests of an invalid, medium-sized session (362 bytes) where the length of any given field was tampered with takes approximately 0.008s, corresponding to an average check rate of 125,000,000 checks per second, or an average check time of 0.000008 milliseconds (8 nanoseconds).

These benchmark times are acceptable for the author of this library.

The average checking time represents the best-case performance scenario, where `c_request_authenticated` is called repeatedly in a tight loop, and data and instruction caches are filled. Performance in real workloads will likely vary.
