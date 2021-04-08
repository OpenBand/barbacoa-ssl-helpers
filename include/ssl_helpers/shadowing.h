#pragma once

#include <string>
#include <chrono>

namespace ssl_helpers {

//Steganography helpers
//

//hide data with XOR of random data
std::string nxor_encode(const std::string& secret);
std::string nxor_decode(const std::string& shadowed_secret);

} // namespace ssl_helpers
