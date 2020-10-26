#include "tests_common.h"

#include <ssl_helpers/hash.h>
#include <ssl_helpers/encoding.h>

#include <functional>

#include <fstream>

#include <boost/filesystem.hpp>

namespace ssl_helpers {
namespace tests {

    template <typename HashFunc>
    void check_hash(HashFunc&& func, const std::string& value)
    {
        static size_t limit = 8;

        auto data = create_test_data();

        auto h_data = func(data, 0);
        auto h_data_short = func(data, limit);

        BOOST_REQUIRE(!h_data.empty());
        BOOST_REQUIRE(!h_data_short.empty());
        BOOST_CHECK_EQUAL(h_data_short.size(), limit);

        auto hex_data = to_hex(h_data);
        auto hex_data_short = to_hex(h_data_short);

        DUMP_STR(hex_data);
        DUMP_STR(hex_data_short);

        BOOST_CHECK_EQUAL(hex_data, value);
        BOOST_CHECK_EQUAL(hex_data_short.size(), 2 * limit);
        BOOST_CHECK_EQUAL(hex_data_short, hex_data.substr(0, 2 * limit));
    }

    template <typename HashFunc>
    void check_hash_from_file(HashFunc&& func, const std::string& value)
    {
        static size_t limit = 8;

        boost::filesystem::path temp = create_binary_data_file(12 * 1024);

        auto h_data = func(temp.generic_string(), 0);
        auto h_data_short = func(temp.generic_string(), limit);

        BOOST_REQUIRE(!h_data.empty());
        BOOST_REQUIRE(!h_data_short.empty());
        BOOST_CHECK_EQUAL(h_data_short.size(), limit);

        auto hex_data = to_hex(h_data);
        auto hex_data_short = to_hex(h_data_short);

        DUMP_STR(hex_data);
        DUMP_STR(hex_data_short);

        BOOST_CHECK_EQUAL(hex_data, value);
        BOOST_CHECK_EQUAL(hex_data_short.size(), 2 * limit);
        BOOST_CHECK_EQUAL(hex_data_short, hex_data.substr(0, 2 * limit));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_SUITE(hash_tests)

    BOOST_AUTO_TEST_CASE(ripemd160_check)
    {
        print_current_test_name();

        check_hash(create_ripemd160, "6568a1b5e4385b845f9fa8511645373a4e5e447f");
    }

    BOOST_AUTO_TEST_CASE(sha256_check)
    {
        print_current_test_name();

        check_hash(create_sha256, "b484737984805aa6909920b1686439f87ccbc584c5110f794071ceb87b9e11cc");
    }

    BOOST_AUTO_TEST_CASE(sha512_check)
    {
        print_current_test_name();

        check_hash(create_sha512, "54f9496e3bb62917967985dc0411f68a5d5c308dd1027ad7159af42e204fe22808c89b09f1d37a3f9a17029bac3b9c54c2f7ed920d6b4985ea7d80ae97533962");
    }

    BOOST_AUTO_TEST_CASE(sha1_check)
    {
        print_current_test_name();

        check_hash(create_sha1, "78211dbb455a4d67ccaf33780bb8eca83ee46578");
    }

    BOOST_AUTO_TEST_CASE(md5_check)
    {
        print_current_test_name();

        check_hash(create_md5, "d4e2207f05e26f5953a741ed27f0b68b");
    }

    BOOST_AUTO_TEST_CASE(pbkdf2_check)
    {
        print_current_test_name();

        const std::string salt { "Salt" };

        check_hash(std::bind(create_pbkdf2_512, std::placeholders::_1, salt, std::placeholders::_2), "377101358e1386fc2a9d0231e0e0dc0e114f395b3c5dd786b5748a6e8a4607575dcc55dceeef8564ca07fa094b90cfd77cd7ae462ef41ac4a88fdf806ff3cdc2");
    }

    BOOST_AUTO_TEST_CASE(pbkdf2_check_details)
    {
        print_current_test_name();

        const std::string password { "Password" };
        const std::string salt { "Salt" };

        BOOST_REQUIRE_EQUAL(to_hex(create_pbkdf2("Password", "Salt", 4096, 128 / 8)), "f66df50f8aaa11e4d9721e1312ff2e66");
        BOOST_REQUIRE_EQUAL(to_hex(create_pbkdf2("Password", "Salt", 8192, 512 / 8)), "a941ccbc34d1ee8ebbd1d34824a419c3dc4eac9cbc7c36ae6c7ca8725e2b618a6ad22241e787af937b0960cf85aa8ea3a258f243e05d3cc9b08af5dd93be046c");
    }

    BOOST_AUTO_TEST_CASE(sha256_from_file_check)
    {
        print_current_test_name();

        check_hash_from_file(create_sha256_from_file, "bada2f8c0db8b0bd6252ba6d9e0e218cd4348af38f5e9974347d079be0612fbf");
    }

    BOOST_AUTO_TEST_CASE(sha512_from_file_check)
    {
        print_current_test_name();

        check_hash_from_file(create_sha512_from_file, "7438cf65032512df6415ef4c3d0358339c2de1a66cf00067f27e18216cfd519025731c24dc4a45de7e9760f366870bd577703b44fd64ac669151f00d7b3926e4");
    }

    BOOST_AUTO_TEST_CASE(sha1_from_file_check)
    {
        print_current_test_name();

        check_hash_from_file(create_sha1_from_file, "d35070f97c80845a4fe4c02fd8d9f8de65f474db");
    }

    BOOST_AUTO_TEST_CASE(ripemd160_from_file_check)
    {
        print_current_test_name();

        check_hash_from_file(create_ripemd160_from_file, "664b93f8d7237ca51016c2b2ddbc8595e8503326");
    }

    BOOST_AUTO_TEST_CASE(md5_from_file_check)
    {
        print_current_test_name();

        check_hash_from_file(create_md5_from_file, "75dcd9dcdc8448f41e08281ecd8de537");
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
