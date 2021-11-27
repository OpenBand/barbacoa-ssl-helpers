#pragma once

#include <string>

namespace ssl_helpers {

// Create hash from input and return left bytes (or all by default)

std::string create_ripemd160(const std::string& data, const size_t limit = 0);

std::string create_sha256(const std::string& data, const size_t limit = 0);

std::string create_sha512(const std::string& data, const size_t limit = 0);

std::string create_sha1(const std::string& data, const size_t limit = 0);

std::string create_md5(const std::string& data, const size_t limit = 0);

std::string create_ripemd160_from_file(const std::string& path, const size_t limit = 0);

std::string create_sha256_from_file(const std::string& path, const size_t limit = 0);

std::string create_sha512_from_file(const std::string& path, const size_t limit = 0);

std::string create_sha1_from_file(const std::string& path, const size_t limit = 0);

std::string create_md5_from_file(const std::string& path, const size_t limit = 0);


// Password-Based Key Derivation Function 2 (PBKDF2) to create hash
// from password to use like the key

std::string create_pbkdf2(const std::string& password, const std::string& salt, int iterations, int key_size);

std::string create_pbkdf2_512(const std::string& password, const std::string& salt, const size_t limit = 0);

} // namespace ssl_helpers
