#include "convert_helper.h"

#if defined(SSL_HELPERS_PLATFORM_MOBILE)
#include <cstdlib>
#include <ctime>
#include <time.h> //POSIX strptime
#else //< SSL_HELPERS_PLATFORM_MOBILE
#include <ctime>
#include <iomanip> // std::put_time, std::get_time
#include <sstream>
#endif //< !SSL_HELPERS_PLATFORM_MOBILE
#include <chrono>

namespace ssl_helpers {
namespace impl {

    uint32_t endian_reverse_u32(uint32_t x)
    {
        return (((x >> 0x18) & 0xFF))
            | (((x >> 0x10) & 0xFF) << 0x08)
            | (((x >> 0x08) & 0xFF) << 0x10)
            | (((x)&0xFF) << 0x18);
    }

    uint8_t from_hex(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;

        SSL_HELPERS_ERROR("Invalid hex character");
        return 0;
    }

    std::string to_hex(const uint8_t* d, uint32_t s)
    {
        std::string r;
        const char* to_hex = "0123456789abcdef";
        for (uint32_t i = 0; i < s; ++i)
            (r += to_hex[(d[i] >> 4)]) += to_hex[(d[i] & 0x0f)];
        return r;
    }

    std::string to_hex(const char* d, uint32_t s)
    {
        return to_hex((const uint8_t*)d, s);
    }

    size_t from_hex(const std::string& hex_str, uint8_t* out_data, size_t out_data_len)
    {
        std::string::const_iterator i = hex_str.begin();
        uint8_t* out_pos = out_data;
        uint8_t* out_end = out_pos + out_data_len;
        while (i != hex_str.end() && out_end != out_pos)
        {
            *out_pos = from_hex(*i) << 4;
            ++i;
            if (i != hex_str.end())
            {
                *out_pos |= from_hex(*i);
                ++i;
            }
            ++out_pos;
        }
        return out_pos - out_data;
    }

    size_t from_hex(const std::string& hex_str, char* out_data, size_t out_data_len)
    {
        return from_hex(hex_str, reinterpret_cast<uint8_t*>(out_data), out_data_len);
    }

    static const char* SSL_HELPERS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S";

#if !defined(SSL_HELPERS_PLATFORM_MOBILE)
#if !defined(SSL_HELPERS_PLATFORM_WINDOWS)
    time_t from_iso_string(const std::string& formatted, bool should_utc)
    {
        std::stringstream ss;

        ss << formatted;

        std::tm tp {};

        ss >> std::get_time(&tp, SSL_HELPERS_TIME_FORMAT);
        if (!ss.fail())
        {
            time_t r = std::mktime(&tp);
            return (should_utc) ? (r + tp.tm_gmtoff) : (r);
        }
        return {};
    }
#else //< !SSL_HELPERS_PLATFORM_WINDOWS
    time_t from_iso_string(const std::string& formatted, bool should_utc)
    {
        std::stringstream ss;

        ss << formatted;

        std::tm tp {};

        ss >> std::get_time(&tp, SSL_HELPERS_TIME_FORMAT);
        if (!ss.fail())
        {
            return (should_utc) ? _mkgmtime(&tp) : std::mktime(&tp);
        }
        return {};
    }
#endif //< SSL_HELPERS_PLATFORM_WINDOWS

    std::string to_iso_string(const time_t t, bool should_utc)
    {
        std::stringstream ss;

        ss << std::put_time((should_utc) ? std::gmtime(&t) : std::localtime(&t), SSL_HELPERS_TIME_FORMAT);

        return ss.str();
    }
#else //< !SSL_HELPERS_PLATFORM_MOBILE
    time_t from_iso_string(const std::string& formatted, bool should_utc)
    {
        std::tm tp {};

        auto call_r = strptime(formatted.c_str(), SSL_HELPERS_TIME_FORMAT, &tp);

        SSL_HELPERS_ASSERT(call_r != NULL, "Can't parse time");

        time_t r = std::mktime(&tp);
        return (should_utc) ? (r + tp.tm_gmtoff) : (r);
    }

    std::string to_iso_string(const time_t t, bool should_utc)
    {
        char buff[100];

        auto call_r = std::strftime(buff, sizeof(buff), SSL_HELPERS_TIME_FORMAT,
                                    (should_utc) ? std::gmtime(&t) : std::localtime(&t));

        SSL_HELPERS_ASSERT(call_r > 0, "Can't format time");

        return { buff };
    }
#endif //< SSL_HELPERS_PLATFORM_MOBILE

} // namespace impl
} // namespace ssl_helpers
