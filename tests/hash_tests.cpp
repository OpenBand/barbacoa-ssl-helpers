#include <fstream>

#include <boost/filesystem.hpp>

#include <ssl_helpers/hash.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


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

        auto h_data = func(default_context_with_crypto_api(), temp.generic_string(), 0);
        auto h_data_short = func(default_context_with_crypto_api(), temp.generic_string(), limit);

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

        check_hash(create_ripemd160, "c30ff71b2127a55e987e7dfa39c205cea5744046");
    }

    BOOST_AUTO_TEST_CASE(sha256_check)
    {
        print_current_test_name();

        check_hash(create_sha256, "98bb864f36b4f16b6f5d0c281ab33bd75930453e10f2b51760272ad165222ddb");
    }

    BOOST_AUTO_TEST_CASE(sha512_check)
    {
        print_current_test_name();

        check_hash(create_sha512, "dbbcf01693e2e4bb8f09713374b30d223a9f871aec6a3df213cc59f0078f62b01cb47a4dce6d3224015f58a7371404f88efae3a4c4c9bd363b0ee12844d067fe");
    }

    BOOST_AUTO_TEST_CASE(sha1_check)
    {
        print_current_test_name();

        check_hash(create_sha1, "0f7fecd54fcf014dbeb9d05f66747e5a4174dd5a");
    }

    BOOST_AUTO_TEST_CASE(md5_check)
    {
        print_current_test_name();

        check_hash(create_md5, "faf3198c9294b938f32f43b20923378c");
    }

    BOOST_AUTO_TEST_CASE(pbkdf2_check)
    {
        print_current_test_name();

        const std::string salt { "Salt" };

        check_hash(std::bind(create_pbkdf2_512, std::placeholders::_1, salt, std::placeholders::_2), "482ad00a7009dc5f1706e9f86becaa0b1c5893e64b35ad2dcc67d5e9bb15fee331d594df9c1bb6f73ff5c67a6c66cc3bb43327f7de5556cd4267b652928224c4");
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
