# Barbacoa SSL Helpers

Helpers for convenient usage of OpenSSL features on C++ and a little more

# Requirements

OpenSSL from 1.0.2g. Tested on 1.1.1j

# Platforms

This lib tested on Ubuntu Ubuntu 16.04-21.04, Windows 10. But there is no any platform-specific features at this library. And one could be compiling and launching library on any platform where OpenSSL is working good enough

# Building

Use CMake. 
For Windows *OpenSSL for Windows* is required. Check 
%OPENSSL_ROOT_DIR%, %OPENSSL_CRYPTO_LIBRARY% environment variables and 
libeay32.dll

# Usage

Some functions require user configuration and preliminary initialization for OpenSSL Libcrypto API. 
Use singleton object _ssl_helpers::context_ if required. For example:

```cpp
// Before any thread creation.
auto buff_sz = some_magic_to_discover_optimal_buffer_size();
auto &ssl_config = context::configurate().enable_libcrypto_api().set_file_buffer_size(buff_sz);
auto &ssl_ctx = ssl_helpers::context::init(ssl_config);

// In business logic if context required.
ssl_helpers::aes_encrypt_file(ssl_ctx, secret_file, secret_key);
ssl_helpers::aes_encrypt_file(ssl_ctx, shredded_file, 
                              ssl_helpers::create_random_string(ssl_ctx, 13));

// In business logic without context ssl_helpers provide ordinary functions.
secret_key = ssl_helpers::create_pbkdf2_512(secret_password, salt);
secret_key_in_memory = ssl_helpers::nxor_encode(secret_key);
secret_key_in_db = ssl_helpers::create_ripemd160(secret_key);
for_debug_log = ssl_helpers::to_hex(secret_key_in_db);
```

Have a look at tests for details.

# Features

* Encoding (baseXX, hex, printable)
* Hash calculation (SHA-X, RIPEMD-160, etc.)
* Cryptography (AES-CBC, AES-GSM, etc.)
* Random data generator

