#include "md5.h"

#include "convert_helper.h"
#include "ssl_helpers_defines.h"
#include "hash_helper.h"

#include <cstring>
#include <cmath>

namespace ssl_helpers {
namespace impl {

    md5::md5() { std::memset(_hash, 0, sizeof(_hash)); }
    md5::md5(const std::string& hex_str)
    {
        from_hex(hex_str, reinterpret_cast<char*>(_hash), sizeof(_hash));
    }

    std::string md5::str() const
    {
        return to_hex(reinterpret_cast<const char*>(_hash), sizeof(_hash));
    }
    md5::operator std::string() const { return str(); }

    char* md5::data() const { return (char*)&_hash[0]; }

    md5::encoder::~encoder() {}
    md5::encoder::encoder()
    {
        reset();
    }

    md5 md5::hash(const char* d, uint32_t dlen)
    {
        encoder e;
        e.write(d, dlen);
        return e.result();
    }
    md5 md5::hash(const std::string& s)
    {
        return hash(s.c_str(), static_cast<uint32_t>(s.size()));
    }

    void md5::encoder::write(const char* d, uint32_t dlen)
    {
        MD5_Update(&_context, d, dlen);
    }
    md5 md5::encoder::result()
    {
        md5 h;
        MD5_Final(reinterpret_cast<uint8_t*>(h.data()), &_context);
        return h;
    }
    void md5::encoder::reset()
    {
        MD5_Init(&_context);
    }

    md5 operator<<(const md5& h1, uint32_t i)
    {
        md5 result;
        shift_l(h1.data(), result.data(), result.data_size(), i);
        return result;
    }
    md5 operator^(const md5& h1, const md5& h2)
    {
        md5 result;
        result._hash[0] = h1._hash[0] ^ h2._hash[0];
        result._hash[1] = h1._hash[1] ^ h2._hash[1];
        result._hash[2] = h1._hash[2] ^ h2._hash[2];
        result._hash[3] = h1._hash[3] ^ h2._hash[3];
        return result;
    }
    bool operator>=(const md5& h1, const md5& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) >= 0;
    }
    bool operator>(const md5& h1, const md5& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) > 0;
    }
    bool operator<(const md5& h1, const md5& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) < 0;
    }
    bool operator!=(const md5& h1, const md5& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) != 0;
    }
    bool operator==(const md5& h1, const md5& h2)
    {
        return std::memcmp(h1._hash, h2._hash, sizeof(h1._hash)) == 0;
    }

} // namespace impl
} //end namespace ssl_helpers
