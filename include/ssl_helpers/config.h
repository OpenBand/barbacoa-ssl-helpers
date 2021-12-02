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

    size_t file_buffer_size() const
    {
        return _file_buffer_size;
    }

    bool is_enabled_libcrypto_api() const
    {
        return _enabled_libcrypto_api;
    }

private:
    size_t _file_buffer_size = 10 * 1024;
    bool _enabled_libcrypto_api = false;
};

} // namespace ssl_helpers
