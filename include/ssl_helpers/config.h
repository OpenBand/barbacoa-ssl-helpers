#pragma once

#include <cstddef>


namespace ssl_helpers {

class config
{
    friend class context;

protected:
    config() = default;

public:
    config(const config&) = default;
    ~config() = default;

    /**
     * Application can provide personal algorithm for buffer size
     * discovering.
     */
    config& set_file_buffer_size(size_t sz);

    /**
     * Required to use:
     *      create_random
     *      aes_* (family functions and classes)
     */
    config& enable_libcrypto_api();

    enum EC_GROUP_DOMAIN : char
    {
        // prime256v1 - Common in OpenSSL manuals
        EC_GROUP_DOMAIN_prime256v1 = 0,
        // secp256k1 - Used in BitShare-based blockchain (Strength = 128)
        EC_GROUP_DOMAIN_secp256k1,
        // secp384r1 - Strength = 192
        EC_GROUP_DOMAIN_secp384r1,
        // secp521r1 - Strength = 256
        EC_GROUP_DOMAIN_secp521r1
    };

    /**
     * Security specific for Elliptic Curve features.
     * To get compromise between security and performance.
     */
    config& set_ec_domain_group(const EC_GROUP_DOMAIN);

    size_t file_buffer_size() const
    {
        return _file_buffer_size;
    }

    bool is_enabled_libcrypto_api() const
    {
        return _enabled_libcrypto_api;
    }

    EC_GROUP_DOMAIN ec_domain_group() const
    {
        return _ec_group_domain;
    }

private:
    size_t _file_buffer_size = 10 * 1024;
    bool _enabled_libcrypto_api = false;
    EC_GROUP_DOMAIN _ec_group_domain = EC_GROUP_DOMAIN_prime256v1;
};

} // namespace ssl_helpers
