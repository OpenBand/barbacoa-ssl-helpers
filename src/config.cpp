#include <ssl_helpers/config.h>

#include "ssl_helpers_defines.h"


namespace ssl_helpers {

config& config::set_file_buffer_size(size_t sz)
{
    SSL_HELPERS_ASSERT(sz > 0, "File buffer required");

    _file_buffer_size = sz;
    return *this;
}

config& config::enable_libcrypto_api()
{
    _enabled_libcrypto_api = true;
    return *this;
}

config& config::set_ec_domain_group(const EC_GROUP_DOMAIN ec_group_domain)
{
    _ec_group_domain = ec_group_domain;
    return *this;
}

} // namespace ssl_helpers
