#include <ssl_helpers/hash.h>

#include "ssl_helpers_defines.h"
#include "ripemd160.h"
#include "sha256.h"
#include "sha512.h"
#include "sha1.h"
#include "md5.h"

#include <fstream>

#include <openssl/evp.h> // PKCS5_PBKDF2_HMAC_SHA1

namespace ssl_helpers {

struct unsigned_int
{
    unsigned_int(uint32_t v = 0)
        : value(v)
    {
    }

    template <typename T>
    unsigned_int(T v)
        : value(v)
    {
    }

    template <typename T>
    operator T() const { return static_cast<T>(value); }

    uint32_t value = 0;
};

inline bool operator<(const unsigned_int& a, const unsigned_int& b)
{
    return a.value < b.value;
}

constexpr const uint32_t PACK_MAX_DEPTH = 10;

template <typename Stream>
inline void pack(Stream& s, const unsigned_int& v, uint32_t depth = PACK_MAX_DEPTH)
{
    SSL_HELPERS_ASSERT(depth > 0);
    uint64_t val = v.value;
    do
    {
        uint8_t b = uint8_t(val) & 0x7f;
        val >>= 7;
        b |= ((val > 0) << 7);
        s.write((char*)&b, 1);
    } while (val);
}

template <typename Stream>
inline void pack(Stream& s, const std::string& v, uint32_t depth = PACK_MAX_DEPTH)
{
    SSL_HELPERS_ASSERT(depth > 0);
    pack(s, unsigned_int((uint32_t)v.size()), depth - 1);
    if (v.size())
        s.write(v.c_str(), (uint32_t)v.size());
}

template <typename HashType>
std::string trim_hash(const HashType& h, const size_t limit)
{
    SSL_HELPERS_ASSERT(limit <= h.data_size());

    size_t sz = limit;
    if (!sz)
        sz = h.data_size();

    return { h.data(), sz };
}

template <typename HashType>
std::string create_hash(const std::string& data, const size_t limit)
{
    HashType h = HashType::hash(data);

    return trim_hash(h, limit);
}

template <typename HashType>
std::string create_hash_from_file(const std::string& path, const size_t limit)
{
    std::ifstream input(path, std::ifstream::binary);

    typename HashType::encoder encoder;
    // A multiple of 2 and 16 and not too small
    // (https://stackoverflow.com/questions/10698339/what-would-be-an-ideal-buffer-size)
    char buff[10 * 1024];

    // Start from 1 byte to read small files less than sizeof(buff)
    for (std::streamsize bytes_read = 1; input.read(buff, sizeof(buff)) || bytes_read > 0;)
    {
        bytes_read = input.gcount();
        if (bytes_read > 0)
        {
            encoder.write(buff, static_cast<uint32_t>(bytes_read));
        }
    }
    HashType h = encoder.result();

    return trim_hash(h, limit);
}

std::string create_ripemd160(const std::string& data, const size_t limit)
{
    return create_hash<impl::ripemd160>(data, limit);
}

std::string create_sha256(const std::string& data, const size_t limit)
{
    return create_hash<impl::sha256>(data, limit);
}

std::string create_sha512(const std::string& data, const size_t limit)
{
    return create_hash<impl::sha512>(data, limit);
}

std::string create_sha1(const std::string& data, const size_t limit)
{
    return create_hash<impl::sha1>(data, limit);
}

std::string create_md5(const std::string& data, const size_t limit)
{
    return create_hash<impl::md5>(data, limit);
}

std::string create_ripemd160_from_file(const std::string& path, const size_t limit)
{
    return create_hash_from_file<impl::ripemd160>(path, limit);
}

std::string create_sha256_from_file(const std::string& path, const size_t limit)
{
    return create_hash_from_file<impl::sha256>(path, limit);
}

std::string create_sha512_from_file(const std::string& path, const size_t limit)
{
    return create_hash_from_file<impl::sha512>(path, limit);
}

std::string create_sha1_from_file(const std::string& path, const size_t limit)
{
    return create_hash_from_file<impl::sha1>(path, limit);
}

std::string create_md5_from_file(const std::string& path, const size_t limit)
{
    return create_hash_from_file<impl::md5>(path, limit);
}

std::string create_pbkdf2(const std::string& password, const std::string& salt, int iterations, int key_size)
{
    std::string key;
    key.resize(static_cast<std::size_t>(key_size));
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), static_cast<int>(password.size()),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), static_cast<int>(salt.size()),
                           iterations, key_size, reinterpret_cast<unsigned char*>(&key[0]));
    return key;
}

std::string create_pbkdf2_512(const std::string& password, const std::string& salt, const size_t limit)
{
    auto h = create_pbkdf2(password, salt, 8192, 512 / 8);

    SSL_HELPERS_ASSERT(limit <= h.size());

    size_t sz = limit;
    if (!sz)
        sz = h.size();

    return { h.data(), sz };
}

} // namespace ssl_helpers
