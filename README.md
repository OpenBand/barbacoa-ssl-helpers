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

# Features

* Encoding (baseXX, hex, printable)
* Hash calculation (SHA-X, RIPEMD-160, etc.)
* Cryptography (AES-CBC, AES-GSM, etc.)
* Random data generator

