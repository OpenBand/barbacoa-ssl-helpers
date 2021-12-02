#pragma once

#include <string>
#include <vector>


namespace ssl_helpers {
namespace impl {

    std::string to_base64(const char* d, size_t s);
    std::string to_base64(const std::vector<char>& data);
    std::vector<char> from_base64(const std::string& base64_str);
    size_t from_base64(const std::string& base64_str, char* out_data, size_t out_data_len);

} // namespace impl
} // namespace ssl_helpers
