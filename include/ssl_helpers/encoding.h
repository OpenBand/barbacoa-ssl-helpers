#pragma once

#include <string>
#include <chrono>

namespace ssl_helpers {

std::string to_hex(const std::string&);
std::string from_hex(const std::string&);

//with '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' alphabet (Bitcoin style)
std::string to_base58(const std::string&);
std::string from_base58(const std::string&);

std::string to_base64(const std::string&);
std::string from_base64(const std::string&);

} // namespace ssl_helpers
