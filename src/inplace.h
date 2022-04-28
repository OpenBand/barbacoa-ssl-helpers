#pragma once

#include <memory>
#include <fstream>
#include <functional>

#include <boost/filesystem.hpp>


namespace ssl_helpers {
namespace impl {

    class file_context
    {
    public:
        file_context(const std::string& path);

        operator bool() const;

        const std::string& path() const
        {
            return _path.generic_string();
        }

        size_t size() const
        {
            return _sz;
        }

        void resize(size_t);

        std::fstream& stream();

    private:
        bool valid(bool check_state) const;

        boost::filesystem::path _path;
        size_t _sz = 0;
        std::unique_ptr<std::fstream> _pf;
    };

    using modification_rule_type = std::function<std::string(const std::string& /*input_chunk*/, bool /*final*/)>;

    using modify_binary_result_type = std::pair<size_t /*input size*/, size_t /*output size*/>;
    modify_binary_result_type modify_binary_inplace(file_context& file, size_t chunk_sz,
                                                    modification_rule_type modification_rule,
                                                    const std::string& header);

} // namespace impl
} // namespace ssl_helpers
