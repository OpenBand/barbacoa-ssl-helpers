#pragma once

#include <string>
#include <chrono>
#include <ctime>

namespace ssl_helpers {

bool is_little_endian();

//simple time converters
std::time_t from_iso_string(const std::string& formatted, bool should_utc = true);
std::string to_iso_string(const std::time_t, bool should_utc = true);

} // namespace ssl_helpers
