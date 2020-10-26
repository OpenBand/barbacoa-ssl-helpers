#include <ssl_helpers/encoding.h>

#include "convert_helper.h"
#include "base58.h"
#include "base64.h"

#include <vector>

namespace ssl_helpers {

std::string to_hex(const std::string& data)
{
    return impl::to_hex(data);
}

std::string from_hex(const std::string& str)
{
    auto sz = static_cast<size_t>(str.size());
    if (sz < 2)
        return {};

    std::vector<char> buf;
    buf.resize(sz / 2);

    impl::from_hex(str, buf.data(), buf.size());
    return { buf.data(), buf.size() };
}

std::string to_base58(const std::string& data)
{
    return impl::to_base58(data.data(), data.size());
}

std::string from_base58(const std::string& str)
{
    std::vector<char> data = impl::from_base58(str);
    return { data.data(), data.size() };
}

std::string to_base64(const std::string& data)
{
    return impl::to_base64(data.data(), data.size());
}

std::string from_base64(const std::string& str)
{
    std::vector<char> data = impl::from_base64(str);
    return { data.data(), data.size() };
}

} // namespace ssl_helpers
