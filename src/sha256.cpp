#include "sha256.h"

#include "convert_helper.h"
#include "ssl_helpers_defines.h"
#include "hash_helper.h"

#include <cstring>
#include <cmath>

namespace ssl_helpers {
namespace impl {

    sha256::sha256() { std::memset(_hash, 0, sizeof(_hash)); }
    sha256::sha256(const char* data, size_t size)
    {
        SSL_HELPERS_ASSERT(size == sizeof(_hash), "sha256: size mismatch");
        memcpy(_hash, data, size);
    }
    sha256::sha256(const std::string& hex_str)
    {
        from_hex(hex_str, reinterpret_cast<char*>(_hash), sizeof(_hash));
    }

    std::string sha256::str() const
    {
        return to_hex(reinterpret_cast<const char*>(_hash), sizeof(_hash));
    }

    char* sha256::data() const { return (char*)&_hash[0]; }

    sha256::encoder::~encoder() {}
    sha256::encoder::encoder()
    {
        reset();
    }

    sha256 sha256::hash(const char* d, uint32_t dlen)
    {
        encoder e;
        e.write(d, dlen);
        return e.result();
    }

    sha256 sha256::hash(const std::string& s)
    {
        return hash(s.c_str(), static_cast<uint32_t>(s.size()));
    }

    sha256 sha256::hash(const sha256& s)
    {
        return hash(s.data(), sizeof(s._hash));
    }

    void sha256::encoder::write(const char* d, uint32_t dlen)
    {
        SHA256_Update(&_context, d, dlen);
    }
    sha256 sha256::encoder::result()
    {
        sha256 h;
        SHA256_Final(reinterpret_cast<uint8_t*>(h.data()), &_context);
        return h;
    }
    void sha256::encoder::reset()
    {
        SHA256_Init(&_context);
    }

    sha256 operator<<(const sha256& h1, uint32_t i)
    {
        sha256 result;
        shift_l(h1.data(), result.data(), result.data_size(), i);
        return result;
    }
    sha256 operator>>(const sha256& h1, uint32_t i)
    {
        sha256 result;
        shift_r(h1.data(), result.data(), result.data_size(), i);
        return result;
    }
    sha256 operator^(const sha256& h1, const sha256& h2)
    {
        sha256 result;
        result._hash[0] = h1._hash[0] ^ h2._hash[0];
        result._hash[1] = h1._hash[1] ^ h2._hash[1];
        result._hash[2] = h1._hash[2] ^ h2._hash[2];
        result._hash[3] = h1._hash[3] ^ h2._hash[3];
        return result;
    }
    bool operator>=(const sha256& h1, const sha256& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) >= 0;
    }
    bool operator>(const sha256& h1, const sha256& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) > 0;
    }
    bool operator<(const sha256& h1, const sha256& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) < 0;
    }
    bool operator!=(const sha256& h1, const sha256& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) != 0;
    }
    bool operator==(const sha256& h1, const sha256& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) == 0;
    }

    uint32_t sha256::approx_log_32() const
    {
        uint16_t lzbits = clz();
        if (lzbits >= 0x100)
            return 0;
        uint8_t nzbits = static_cast<uint8_t>(0xFF - lzbits);
        size_t offset = static_cast<size_t>(lzbits >> 3);
        uint8_t* my_bytes = reinterpret_cast<uint8_t*>(data());
        size_t n = data_size();
        uint32_t y = (uint32_t(my_bytes[offset]) << 0x18)
            | (uint32_t(offset + 1 < n ? my_bytes[offset + 1] : 0) << 0x10)
            | (uint32_t(offset + 2 < n ? my_bytes[offset + 2] : 0) << 0x08)
            | (uint32_t(offset + 3 < n ? my_bytes[offset + 3] : 0));
        //
        // lzbits&7 == 7 : 00000001 iff nzbits&7 == 0
        // lzbits&7 == 6 : 0000001x iff nzbits&7 == 1
        // lzbits&7 == 5 : 000001xx iff nzbits&7 == 2
        //
        y >>= (nzbits & 7);
        y ^= 1 << 0x18;
        y |= uint32_t(nzbits) << 0x18;
        return y;
    }

    void sha256::set_to_inverse_approx_log_32(uint32_t x)
    {
        uint8_t nzbits = uint8_t(x >> 0x18);
        _hash[0] = 0;
        _hash[1] = 0;
        _hash[2] = 0;
        _hash[3] = 0;
        if (nzbits == 0)
            return;
        uint8_t x0 = uint8_t((x)&0xFF);
        uint8_t x1 = uint8_t((x >> 0x08) & 0xFF);
        uint8_t x2 = uint8_t((x >> 0x10) & 0xFF);
        uint8_t* my_bytes = reinterpret_cast<uint8_t*>(data());
        my_bytes[0x1F] = x0;
        my_bytes[0x1E] = x1;
        my_bytes[0x1D] = x2;
        my_bytes[0x1C] = 1;

        if (nzbits <= 0x18)
        {
            (*this) = (*this) >> (0x18 - nzbits);
        }
        else
            (*this) = (*this) << (nzbits - 0x18);
    }

    double sha256::inverse_approx_log_32_double(uint32_t x)
    {
        uint8_t nzbits = uint8_t(x >> 0x18);
        if (nzbits == 0)
            return 0.0;
        uint32_t b = 1 << 0x18;
        uint32_t y = (x & (b - 1)) | b;
        return std::ldexp(y, int(nzbits) - 0x18);
    }

    uint16_t sha256::clz() const
    {
        const uint8_t* my_bytes = reinterpret_cast<uint8_t*>(data());
        size_t size = data_size();
        size_t lzbits = 0;
        static const uint8_t char2lzbits[] = {
            // 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
            8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        size_t i = 0;

        while (true)
        {
            uint8_t c = my_bytes[i];
            lzbits += char2lzbits[c];
            if (c != 0)
                break;
            ++i;
            if (i >= size)
                return 0x100;
        }

        return static_cast<uint16_t>(lzbits);
    }

} // namespace impl
} //end namespace ssl_helpers
