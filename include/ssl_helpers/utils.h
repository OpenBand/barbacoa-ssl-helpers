#pragma once

#include <string>
#include <chrono>
#include <ctime>


namespace ssl_helpers {

bool is_little_endian();

// Convert readable ISO-datetime string to UNIX time

std::time_t from_iso_string(const std::string& formatted, bool should_utc = true);

// Convert UNIX time to readable ISO-datetime

std::string to_iso_string(const std::time_t, bool should_utc = true);

} // namespace ssl_helpers
