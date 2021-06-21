#include "sha1.h"

#include "convert_helper.h"
#include "ssl_helpers_defines.h"
#include "hash_helper.h"

#include <cstring>
#include <cmath>

namespace ssl_helpers {
namespace impl {

    sha1::sha1() { std::memset(_hash, 0, sizeof(_hash)); }
    sha1::sha1(const std::string& hex_str)
    {
        from_hex(hex_str, reinterpret_cast<char*>(_hash), sizeof(_hash));
    }

    std::string sha1::str() const
    {
        return to_hex(reinterpret_cast<const char*>(_hash), sizeof(_hash));
    }
    sha1::operator std::string() const { return str(); }

    char* sha1::data() const { return (char*)&_hash[0]; }

    sha1::encoder::~encoder() {}
    sha1::encoder::encoder()
    {
        reset();
    }

    sha1 sha1::hash(const char* d, uint32_t dlen)
    {
        encoder e;
        e.write(d, dlen);
        return e.result();
    }
    sha1 sha1::hash(const std::string& s)
    {
        return hash(s.c_str(), static_cast<uint32_t>(s.size()));
    }

    void sha1::encoder::write(const char* d, uint32_t dlen)
    {
        SHA1_Update(&_context, d, dlen);
    }
    sha1 sha1::encoder::result()
    {
        sha1 h;
        SHA1_Final(reinterpret_cast<uint8_t*>(h.data()), &_context);
        return h;
    }
    void sha1::encoder::reset()
    {
        SHA1_Init(&_context);
    }

    sha1 operator<<(const sha1& h1, uint32_t i)
    {
        sha1 result;
        shift_l(h1.data(), result.data(), result.data_size(), i);
        return result;
    }
    sha1 operator^(const sha1& h1, const sha1& h2)
    {
        sha1 result;
        result._hash[0] = h1._hash[0] ^ h2._hash[0];
        result._hash[1] = h1._hash[1] ^ h2._hash[1];
        result._hash[2] = h1._hash[2] ^ h2._hash[2];
        result._hash[3] = h1._hash[3] ^ h2._hash[3];
        result._hash[4] = h1._hash[4] ^ h2._hash[4];
        return result;
    }
    bool operator>=(const sha1& h1, const sha1& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) >= 0;
    }
    bool operator>(const sha1& h1, const sha1& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) > 0;
    }
    bool operator<(const sha1& h1, const sha1& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) < 0;
    }
    bool operator!=(const sha1& h1, const sha1& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) != 0;
    }
    bool operator==(const sha1& h1, const sha1& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) == 0;
    }

} // namespace impl
} //end namespace ssl_helpers
