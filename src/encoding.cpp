#include <ssl_helpers/encoding.h>

#include "convert_helper.h"
#include "base58.h"
#include "base64.h"

#include <algorithm>
#include <set>

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

namespace {
    class printable_index
    {
    public:
        printable_index(const char* data)
        {
            const char* pch = data;
            while (*pch)
            {
                _index.emplace(*pch);
                pch++;
            }
        }

        bool operator()(char ch)
        {
            auto it = _index.find(ch);
            return _index.end() != it;
        }

    private:
        std::set<char> _index;

        // Python string.printable:
    } __printable_bytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c";
} // namespace

std::string to_printable(const std::string& data, char replace, const std::string& exclude)
{
    // TODO: for better performance use ASCII index comparison algorithm instead that
    // but this must have enough performance for most cases

    std::string converted(data.begin(), data.end());
    printable_index indexed_exclude(exclude.c_str()); //suppose this list is short enough

    std::replace_if(
        converted.begin(), converted.end(), [&](char ch) {
            return !__printable_bytes(ch) || indexed_exclude(ch);
        },
        replace);

    return converted;
}

} // namespace ssl_helpers
