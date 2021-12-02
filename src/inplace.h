#pragma once

#include <functional>

#include <boost/filesystem.hpp>


namespace ssl_helpers {
namespace impl {

    using modification_rule_type = std::function<std::string(const std::string& /*input_chunk*/, size_t /*current_byte*/)>;

    using modify_binary_result_type = std::pair<size_t /*input size*/, size_t /*output size*/>;
    modify_binary_result_type modify_binary_inplace(const std::string& path, size_t chunk_sz,
                                                    modification_rule_type modification_rule,
                                                    size_t pass_header_bytes);

} // namespace impl
} // namespace ssl_helpers
