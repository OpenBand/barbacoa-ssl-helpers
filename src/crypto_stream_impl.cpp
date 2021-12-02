#include <ssl_helpers/shadowing.h>

#include "crypto_stream_impl.h"


namespace ssl_helpers {
namespace impl {

    __aes_encryption_stream::__aes_encryption_stream(const context& ctx,
                                                     const std::string& key, const std::string& add)
        : _add(add)
    {
        if (!key.empty())
            _key_shadow = nxor_encode_sec(ctx, key);
    }

    std::string __aes_encryption_stream::start(const std::string& key, const std::string& add)
    {
        SSL_HELPERS_ASSERT(!key.empty() || !_key_shadow.empty(), "Key required");

        return _sm.start(key.empty() ? nxor_decode(_key_shadow) : key, add.empty() ? _add : add);
    }

    std::string __aes_encryption_stream::encrypt(const std::string& plain_chunk)
    {
        return _sm.process(plain_chunk);
    }

    gcm_tag_type __aes_encryption_stream::finalize()
    {
        return _sm.finalize();
    }

    size_t __aes_encryption_stream::tag_size()
    {
        return std::tuple_size<gcm_tag_type>::value;
    }

    __aes_decryption_stream::__aes_decryption_stream(const context& ctx,
                                                     const std::string& key, const std::string& add)
        : _add(add)
    {
        if (!key.empty())
            _key_shadow = nxor_encode_sec(ctx, key);
    }

    void __aes_decryption_stream::start(const std::string& key, const std::string& add)
    {
        _sm.start(key.empty() ? nxor_decode(_key_shadow) : key, add.empty() ? _add : add);
    }

    std::string __aes_decryption_stream::decrypt(const std::string& cipher_chunk)
    {
        return _sm.process(cipher_chunk);
    }

    void __aes_decryption_stream::finalize(const gcm_tag_type& tag)
    {
        _sm.finalize(tag);
    }

} // namespace impl

} // namespace ssl_helpers
