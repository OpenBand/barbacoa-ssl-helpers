#include <cstring>
#include <array>

#include <ssl_helpers/shadowing.h>
#include <ssl_helpers/random.h>

#include "ssl_helpers_defines.h"


namespace ssl_helpers {

namespace impl {

    using key_type = uint64_t;

    constexpr size_t key_sz = sizeof(key_type);

    std::string encode_noise_xor(const std::string& secret, key_type noise)
    {
        SSL_HELPERS_ASSERT(!secret.empty());

        std::string result;

        size_t result_sz = secret.size() + key_sz;
        result.reserve(result_sz);

        std::array<char, key_sz> key;
        std::memcpy(key.data(), (const char*)&noise, key_sz);

        result.append(key.data(), key_sz);

        size_t data_offset = key_sz;
        size_t cipher_offset = 0;
        for (size_t ci = data_offset; ci < result_sz; ++ci)
        {
            if (cipher_offset >= key_sz)
                cipher_offset = 0;
            result.push_back(secret[ci - data_offset] ^ key[cipher_offset++]);
        }

        return result;
    }

    std::string decode_noise_xor(const std::string& crypted)
    {
        SSL_HELPERS_ASSERT(!crypted.empty() && crypted.size() > key_sz);

        std::string result;

        auto&& pcrypted = crypted.data();

        result.resize(crypted.size() - key_sz);

        size_t data_offset = key_sz;
        size_t cipher_offset = 0;
        for (size_t ci = 0; ci < result.size(); ++ci)
        {
            if (cipher_offset >= key_sz)
                cipher_offset = 0;
            result[ci] = pcrypted[ci + data_offset] ^ pcrypted[cipher_offset++];
        }

        return result;
    }
} // namespace impl

std::string nxor_encode_sec(const context& ctx, const std::string& secret)
{
    try
    {
        return impl::encode_noise_xor(secret, static_cast<impl::key_type>(create_random(ctx)));
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ERROR(e.what());
    }
    return {};
}

std::string nxor_encode(const std::string& secret)
{
    return impl::encode_noise_xor(secret, static_cast<impl::key_type>(create_pseudo_random_from_time()));
}

std::string nxor_decode(const std::string& shadowed_secret)
{
    return impl::decode_noise_xor(shadowed_secret);
}

} // namespace ssl_helpers
