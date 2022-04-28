#include <fstream>

#include <boost/filesystem.hpp>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    std::string create_test_data(const size_t size)
    {
        static std::string data_ = "test";
        std::string data;
        size_t ci = 0;
        while (data.size() < size)
        {
            data.append(data_);
            data.push_back(ci);
        }
        return data.substr(0, size);
    }

    boost::filesystem::path create_binary_data_file(const size_t file_size)
    {
        BOOST_REQUIRE_GT(file_size, 0u);

        boost::filesystem::path temp = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
        std::ofstream output { temp.generic_string(), std::ofstream::binary };

        constexpr size_t BUFF_SZ = 1024;
        unsigned char buff[BUFF_SZ];
        size_t ci = 0;
        size_t total = 0;
        while (true)
        {
            std::memset(buff, 0, sizeof(buff));
            auto* pbuff_offset = buff;
            for (auto cj = 0; cj < BUFF_SZ / sizeof(float); ++cj)
            {
                float fl = 9999 + ci++;
                std::memcpy(pbuff_offset, &fl, sizeof(float));
                pbuff_offset += sizeof(float);
            }

            size_t to_write = std::min(sizeof(buff), file_size - total);
            output.write(reinterpret_cast<char*>(buff), to_write);
            total += to_write;
            if (total >= file_size)
                break;
        }

        return temp;
    }

    boost::filesystem::path create_readable_data_file(
        const std::string& content,
        const size_t file_size,
        const std::string& file_name)
    {
        BOOST_REQUIRE_GT(file_size, 0u);

        using path = boost::filesystem::path;
        path temp = boost::filesystem::temp_directory_path() / ((file_name.empty()) ? boost::filesystem::unique_path() : path { file_name });
        std::ofstream output { temp.generic_string(), std::ofstream::binary };

        std::string readable;
        if (!content.empty())
            readable = content;
        else
        {
            constexpr size_t BUFF_SZ = 1024;
            readable = std::string(BUFF_SZ, 'A');
        }
        size_t total = 0;
        while (true)
        {

            size_t to_write = std::min(readable.size(), file_size - total);
            output.write(readable.data(), to_write);
            total += to_write;
            if (total >= file_size)
                break;
        }

        return temp;
    }

    std::string get_file_content(const boost::filesystem::path& path)
    {
        std::ifstream f(path.generic_string(), std::ifstream::binary | std::ifstream::out);

        std::stringstream ss;
        ss << f.rdbuf();

        return ss.str();
    }

    void print_current_test_name()
    {
        static uint32_t test_counter = 0;

        std::stringstream ss;

        ss << "TEST (";
        ss << ++test_counter;
        ss << ") - [";
        ss << boost::unit_test::framework::current_test_case().p_name;
        ss << "]";
        DUMP_STR(ss.str());
    }

    context& default_context_with_crypto_api()
    {
        return context::init(context::configurate().enable_libcrypto_api());
    }

} // namespace tests
} // namespace ssl_helpers
