#pragma once

#include <string>
#include <chrono>

namespace ssl_helpers {

// Steganography helper to hide data in memory
// with XOR of random data

// Encrypt data

std::string nxor_encode(const std::string& secret);

// Decrypt data

std::string nxor_decode(const std::string& shadowed_secret);

} // namespace ssl_helpers
