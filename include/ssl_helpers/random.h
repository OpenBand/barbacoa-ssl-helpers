#pragma once

#include <string>

namespace ssl_helpers {

uint32_t create_pseudo_random_from_time(const uint32_t offset = 0);
std::string create_pseudo_random_string_from_time(const uint32_t offset = 0);

//generate OpenSSL random value
uint64_t create_random(const uint64_t offset = 0);

} // namespace ssl_helpers
