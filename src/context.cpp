#include <memory>

#include <ssl_helpers/context.h>

#include "openssl_crypto_api.h"


namespace ssl_helpers {

class __internal_context
{
public:
    static context& create_context(const config&);

    static std::unique_ptr<context> singleton_context;
};

context& __internal_context::create_context(const config& config_)
{
    singleton_context.reset(new context(config_));
    return *singleton_context;
}

std::unique_ptr<context> __internal_context::singleton_context;

context::context(const config& config_)
    : _config(config_)
{
}

config context::configurate()
{
    return {};
}

context& context::init(const config& config_)
{
    auto& ctx = __internal_context::create_context(config_);
    if (ctx().is_enabled_libcrypto_api())
    {
        impl::init_openssl_crypto_api();
    }
    return ctx;
}

const config& context::operator()() const
{
    return _config;
}

} // namespace ssl_helpers
