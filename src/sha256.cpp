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

} // namespace impl
} //end namespace ssl_helpers
