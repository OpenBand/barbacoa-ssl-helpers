#pragma once

#include "ssl_helpers_defines.h"

#include <cstdint>
#include <string>
#include <stdexcept>

namespace ssl_helpers {
namespace impl {

    uint32_t endian_reverse_u32(uint32_t x);

    std::string to_hex(const char* d, uint32_t s);
    std::string to_hex(const uint8_t* d, uint32_t s);

    template <typename T>
    std::string to_hex(const T& data)
    {
        if (!data.empty())
            return to_hex(data.data(), static_cast<uint32_t>(data.size()));
        return {};
    }

    size_t from_hex(const std::string& hex_str, char* out_data, size_t out_data_len);
    size_t from_hex(const std::string& hex_str, uint8_t* out_data, size_t out_data_len);

    template <typename T>
    void from_hex(const std::string& hex_str, T& data)
    {
        SSL_HELPERS_ASSERT(!hex_str.empty() && data.size() == hex_str.size() / 2);

        size_t r = from_hex(hex_str, data.data(), data.size());
        SSL_HELPERS_ASSERT(r == hex_str.size() / 2);
    }

    time_t from_iso_string(const std::string& formatted, bool should_utc = true);
    std::string to_iso_string(const time_t, bool should_utc = true);

} // namespace impl
} // namespace ssl_helpers
