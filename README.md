# cookie_check

Checking "importantness" of encrypted Phoenix 1.7 cookie sessions through a C API, via safe Rust. Does not panic back into C. Requires openssl.

## Parameters

```elixir
secret    = config :myapp, MyAppWeb.EndPoint, secret_key_base: ... # your secret key
salt      = plug Plug.Session, encryption_salt: ... # your encryption salt (often "signed encrypted cookie")
sign_salt = plug Plug.Session, signing_salt: ... # your signing salt (often "signed cookie")
```

## C example usage

See the example instructions in cookie_test.c.

## OpenResty example usage

Requires the [`resty.cookie`](https://github.com/cloudflare/lua-resty-cookie) module.

```nginx
upstream example_upstream {
  server localhost:8080 fail_timeout=0;
}

proxy_cache_path /var/lib/nginx/proxy_cache levels=1:2 keys_zone=example_cache:8m max_size=100m inactive=1m;

init_by_lua_block {
  ck = require("resty.cookie")
  ffi = require("ffi")

  ffi.cdef [[
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

  typedef struct c_ip_data {
      const uint8_t *ip;
      size_t iplen;
  } c_ip_data;

  int c_request_authenticated(c_key_data const *key, c_cookie_data const *cookie);
  int c_ip_authenticated(c_key_data const *key, c_cookie_data const *cookie, c_ip_data const *ip);
  void c_derive_key(c_key_data *key);
  ]]

  ccheck = ffi.load("/srv/cookie_check/target/release/libcookie_check.so")
  keydata = ffi.new("struct c_key_data", {
    secret       = "WdKlFbaMpXN8S5O1KpRWQfMu8VgfV4i8ojNqqR6vOkFDSyAKTb9ckFJ0pDAb9vwa",
    secretlen    = 63,
    salt         = "signed encrypted cookie",
    saltlen      = 23,
    sign_salt    = "signed cookie"
    sign_saltlen = 13
  })

  ccheck.c_derive_key(keydata)
}

server {
  listen 80 default;

  location / {
    set $target "@proxy_cache";

    rewrite_by_lua_block {
      if string.lower(ngx.req.get_method()) ~= "get" then
        ngx.var.target = "@proxy"
        return
      end    

      local cookie, err = ck:new()
      if not cookie then
        return
      end

      local session, err = cookie:get("_my_app_web_key")
      if not session then
        return
      end

      local cookiedata = ffi.new("struct c_cookie_data", {
        cookie    = session,
        cookielen = string.len(session)
      })

      local ipdata = ffi.new("struct c_ip_data", {
        ip    = ngx.var.remote_ip,
        iplen = string.len(ngx.var.remote_ip)
      })

      if ccheck.c_ip_authenticated(keydata, cookiedata, ipdata) ~= 0 then
        ngx.var.target = "@proxy"
      end
    }

    try_files $uri $target;
  }

  location @proxy {
    proxy_pass http://example_upstream;
    proxy_redirect off;
  }

  location @proxy_cache {
    proxy_cache example_cache;
    proxy_ignore_headers X-Accel-Expires Expires Cache-Control Cookie Set-Cookie;
    proxy_cache_valid any 1m;
    proxy_pass  http://example_upstream;
    proxy_set_header   Cookie           '';
    proxy_set_header   Set-Cookie       '';
    proxy_hide_header  Cache-Control;
  }
}
```

## Performance

This library is thread safe, and throughput should scale linearly with the core count of the machine. Benchmark times reported below reflect single core performance, but a machine with 4 cores should theoretically be able to perform 4 times as many checks per second.

Performing 1 million tests of a valid, medium-sized session (441 bytes) on a 5950X CPU takes approximately 1.892 seconds, corresponding to an average check rate of 528,500 checks per second, or an average check time of 1.892 microseconds.

Performing 1 million tests of an invalid, medium-sized session (441 bytes) where the data was tampered with takes approximately 1.754s, corresponding to an average check rate of 570,100 checks per second, or an average check time of 1.754 microseconds.

These benchmark times are acceptable for the author of this library.

The average checking time represents the best-case performance scenario, where `c_request_authenticated` is called repeatedly in a tight loop, and data and instruction caches are filled. Performance in real workloads will likely vary.
