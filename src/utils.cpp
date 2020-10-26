#include <ssl_helpers/utils.h>

#include "convert_helper.h"

namespace ssl_helpers {

bool is_little_endian()
{
    int num = 1;
    return *reinterpret_cast<char*>(&num) == 1;
}

std::time_t from_iso_string(const std::string& formatted, bool should_utc)
{
    return impl::from_iso_string(formatted, should_utc);
}

std::string to_iso_string(const std::time_t time, bool should_utc)
{
    return impl::to_iso_string(time, should_utc);
}

} // namespace ssl_helpers
