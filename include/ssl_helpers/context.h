#pragma once

#include <ssl_helpers/config.h>


namespace ssl_helpers {

class context
{
    friend class __internal_context;

protected:
    context(const config&);

public:
    static config configurate();

    static context& init(const config&);

    const config& operator()() const;

private:
    config _config;
};

} // namespace ssl_helpers
