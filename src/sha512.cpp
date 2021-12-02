#include <cstring>
#include <cmath>

#include "convert_helper.h"
#include "ssl_helpers_defines.h"
#include "hash_helper.h"
#include "sha512.h"


namespace ssl_helpers {
namespace impl {

    sha512::sha512() { std::memset(_hash, 0, sizeof(_hash)); }

    sha512::sha512(const std::string& hex_str)
    {
        from_hex(hex_str, reinterpret_cast<char*>(_hash), sizeof(_hash));
    }

    std::string sha512::str() const
    {
        return to_hex(reinterpret_cast<const char*>(_hash), sizeof(_hash));
    }

    sha512::operator std::string() const { return str(); }

    char* sha512::data() const { return (char*)&_hash[0]; }

    sha512::encoder::~encoder() {}

    sha512::encoder::encoder()
    {
        reset();
    }

    sha512 sha512::hash(const char* d, uint32_t dlen)
    {
        encoder e;
        e.write(d, dlen);
        return e.result();
    }

    sha512 sha512::hash(const std::string& s)
    {
        return hash(s.c_str(), static_cast<uint32_t>(s.size()));
    }

    void sha512::encoder::write(const char* d, uint32_t dlen)
    {
        SHA512_Update(&_context, d, dlen);
    }

    sha512 sha512::encoder::result()
    {
        sha512 h;
        SHA512_Final(reinterpret_cast<uint8_t*>(h.data()), &_context);
        return h;
    }

    void sha512::encoder::reset()
    {
        SHA512_Init(&_context);
    }

    sha512 operator<<(const sha512& h1, uint32_t i)
    {
        sha512 result;
        shift_l(h1.data(), result.data(), result.data_size(), i);
        return result;
    }

    sha512 operator^(const sha512& h1, const sha512& h2)
    {
        sha512 result;
        result._hash[0] = h1._hash[0] ^ h2._hash[0];
        result._hash[1] = h1._hash[1] ^ h2._hash[1];
        result._hash[2] = h1._hash[2] ^ h2._hash[2];
        result._hash[3] = h1._hash[3] ^ h2._hash[3];
        result._hash[4] = h1._hash[4] ^ h2._hash[4];
        result._hash[5] = h1._hash[5] ^ h2._hash[5];
        result._hash[6] = h1._hash[6] ^ h2._hash[6];
        result._hash[7] = h1._hash[7] ^ h2._hash[7];
        return result;
    }

    bool operator>=(const sha512& h1, const sha512& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) >= 0;
    }

    bool operator>(const sha512& h1, const sha512& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) > 0;
    }

    bool operator<(const sha512& h1, const sha512& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) < 0;
    }

    bool operator!=(const sha512& h1, const sha512& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) != 0;
    }

    bool operator==(const sha512& h1, const sha512& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) == 0;
    }

} // namespace impl
} // namespace ssl_helpers
