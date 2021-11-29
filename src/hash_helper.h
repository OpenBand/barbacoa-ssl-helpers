#pragma once

#include <cstdint>
#include <cstring>

namespace ssl_helpers {
namespace impl {

    inline void shift_l(const uint8_t* in, uint8_t* out, size_t n, unsigned int i)
    {
        if (i < n)
        {
            std::memcpy(out, in + i, n - i);
        }
        else
        {
            i = static_cast<unsigned int>(n);
        }
        std::memset(out + (n - i), 0, i);
    }

    inline void shift_l(const char* in, char* out, size_t n, unsigned int i)
    {
        const uint8_t* in8 = reinterpret_cast<const uint8_t*>(in);
        uint8_t* out8 = reinterpret_cast<uint8_t*>(out);

        if (i >= 8)
        {
            shift_l(in8, out8, n, i / 8);
            i &= 7;
            in8 = out8;
        }

        size_t p;
        for (p = 0; p < n - 1; ++p)
            out8[p] = (in8[p] << i) | (in8[p + 1] >> (8 - i));
        out8[p] = in8[p] << i;
    }

    inline void shift_r(const uint8_t* in, uint8_t* out, size_t n, unsigned int i)
    {
        if (i < n)
        {
            std::memcpy(out + i, in, n - i);
        }
        else
        {
            i = static_cast<unsigned int>(n);
        }
        std::memset(out, 0, i);
    }

    inline void shift_r(const char* in, char* out, size_t n, unsigned int i)
    {
        const uint8_t* in8 = reinterpret_cast<const uint8_t*>(in);
        uint8_t* out8 = reinterpret_cast<uint8_t*>(out);

        if (i >= 8)
        {
            shift_r(in8, out8, n, i / 8);
            i &= 7;
            in8 = out8;
        }

        size_t p;
        for (p = n - 1; p > 0; --p)
            out8[p] = (in8[p] >> i) | (in8[p - 1] << (8 - i));
        out8[p] = in8[p] >> i;
    }

} // namespace impl
} // namespace ssl_helpers
