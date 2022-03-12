#pragma once

#include <string>
#include <functional>
#include <sstream>

#include <boost/test/unit_test.hpp>
#include <boost/filesystem/path.hpp>

#include <ssl_helpers/context.h>


namespace ssl_helpers {
namespace tests {

    template <typename Stream>
    void dump_str(Stream& s, const std::string& str)
    {
        s << ">>>\n";
        s << str << '\n';
        s << "<<<\n";
        s << std::flush;
    }

    std::string create_test_data(const size_t size = 13);
    boost::filesystem::path create_binary_data_file(const size_t file_size);
    boost::filesystem::path create_readable_data_file(const size_t file_size, const std::string& file_name = {});

    void print_current_test_name();

    context& default_context_with_crypto_api();

} // namespace tests
} // namespace ssl_helpers

#ifdef NDEBUG
#define DUMP_STR(str) (str)
#else
#include <iostream>

#define DUMP_STR(str) \
    ssl_helpers::tests::dump_str(std::cerr, str)
#endif
