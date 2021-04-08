#include "crypto_stream_impl.h"

#include <ssl_helpers/shadowing.h>

namespace ssl_helpers {
namespace impl {

    aes_encryption_stream_impl::aes_encryption_stream_impl(const std::string& key, const std::string& add)
        : _add(add)
    {
        if (!key.empty())
            _key_shadow = nxor_encode(key);
    }

    std::string aes_encryption_stream_impl::start(const std::string& key, const std::string& add)
    {
        SSL_HELPERS_ASSERT(!key.empty() || !_key_shadow.empty(), "Key required");

        return _sm.start(key.empty() ? nxor_decode(_key_shadow) : key, add.empty() ? _add : add);
    }

    std::string aes_encryption_stream_impl::encrypt(const std::string& plain_chunk)
    {
        return _sm.process(plain_chunk);
    }

    std::string aes_encryption_stream_impl::finalize()
    {
        return _sm.finalize();
    }

    size_t aes_encryption_stream_impl::tag_size() const
    {
        return std::tuple_size<gcm_tag_type>::value;
    }

    aes_decryption_stream_impl::aes_decryption_stream_impl(const std::string& key, const std::string& add)
        : _add(add)
    {
        if (!key.empty())
            _key_shadow = nxor_encode(key);
    }

    void aes_decryption_stream_impl::start(const std::string& key, const std::string& add)
    {
        _sm.start(key.empty() ? nxor_decode(_key_shadow) : key, add.empty() ? _add : add);
    }

    std::string aes_decryption_stream_impl::decrypt(const std::string& cipher_chunk)
    {
        return _sm.process(cipher_chunk);
    }

    void aes_decryption_stream_impl::finalize(const std::string& tag)
    {
        _sm.finalize(tag);
    }

} // namespace impl

} // namespace ssl_helpers
