#pragma once

#include <array>
#include <string>

namespace ssl_helpers {

using aes_256bit_type = std::array<char, 16>;

using aes_tag_type = aes_256bit_type;

using aes_salt_type = aes_256bit_type;
using salted_key_type = std::pair<std::string /*encryption key*/, aes_salt_type /*random salt*/>;

std::string aes_to_string(const aes_256bit_type&);
aes_256bit_type aes_from_string(const std::string&);

using flip_session_type = std::pair<std::string /*cipher data*/, std::string /*session key*/>;

namespace impl {
    class __aes_encryption_stream;
    class __aes_decryption_stream;
} // namespace impl

} // namespace ssl_helpers
