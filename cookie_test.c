// gcc -Wall -O2 cookie_test.c -o cookie_test $PWD/target/release/libcookie_check.so -lssl -lcrypto -ldl -lpthread

#include <string.h>
#include <stdio.h>
#include <stdint.h>

// Size: 112 bytes
typedef struct c_key_data {
    const char *secret;
    size_t secretlen;
    const char *salt;
    size_t saltlen;
    const char *sign_salt;
    size_t sign_saltlen;
    uint8_t key[32];
    uint8_t sign_key[32];
} c_key_data;

// Size: 16 bytes
typedef struct c_cookie_data {
    const char *cookie;
    size_t cookielen;
} c_cookie_data;

// Size: 16 bytes
typedef struct c_ip_data {
    const char *ip;
    size_t iplen;
} c_ip_data;

int c_request_authenticated(c_key_data const *key, c_cookie_data const *cookie);
int c_ip_authenticated(c_key_data const *key, c_cookie_data const *cookie, c_ip_data const *ip);
void c_derive_key(c_key_data *key);

int main(int argc, char *argv[])
{
    c_key_data key;
    c_cookie_data cookie;

    // Example secret, generated with `mix phx.gen.secret`
    key.secret       = "WdKlFbaMpXN8S5O1KpRWQfMu8VgfV4i8ojNqqR6vOkFDSyAKTb9ckFJ0pDAb9vwa";
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
