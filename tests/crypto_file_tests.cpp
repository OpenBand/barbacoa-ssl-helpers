#include <boost/filesystem.hpp>

#include <ssl_helpers/crypto.h>
#include <ssl_helpers/hash.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    static const std::string FILE_CONTENT = R"txt(
        I must not fear.
        Fear is the mind-killer.
        Fear is the little-death that brings total obliteration.
        I will face my fear.
        I will permit it to pass over me and through me.
        And when it has gone past, I will turn the inner eye to see its path.
        Where the fear has gone there will be nothing. Only I will remain.
                                    )txt";

    BOOST_AUTO_TEST_SUITE(crypto_tests)

    BOOST_AUTO_TEST_CASE(small_file_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        tag = from_hex(stored_tag);

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag);

        BOOST_REQUIRE_EQUAL(FILE_CONTENT, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_with_saved_tag_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, true);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, {}, true);

        BOOST_REQUIRE_EQUAL(FILE_CONTENT, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_with_saved_tag_double_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, true);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag, true);

        BOOST_REQUIRE_EQUAL(FILE_CONTENT, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_without_marker_header_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_decrypt_file(ctx, temp.generic_string(), key, "", tag);

        BOOST_REQUIRE_EQUAL(FILE_CONTENT, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_wrong_key_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        tag = from_hex(stored_tag);

        BOOST_REQUIRE_THROW(aes_decrypt_file(ctx, temp.generic_string(), wrong_key, encrypted_file_marker, tag), std::logic_error);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_wrong_key_without_tag_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(FILE_CONTENT.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(FILE_CONTENT, FILE_CONTENT.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_decrypt_file(ctx, temp.generic_string(), wrong_key, encrypted_file_marker);

        DUMP_STR(to_printable(get_file_content(temp)));

        BOOST_REQUIRE_NE(FILE_CONTENT, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string encrypted_file_marker = "XXX";

        auto& ctx = default_context_with_crypto_api();

        boost::filesystem::path temp = create_readable_data_file("LoNg TeSt"
                                                                 "\n",
                                                                 ctx().file_buffer_size() * 10, boost::unit_test::framework::current_test_case().p_name);

        auto initial_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(initial_sha256);

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag);

        auto last_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(last_sha256);

        BOOST_REQUIRE_EQUAL(initial_sha256, last_sha256);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_without_corruption_by_wrong_psw_check)
    {
        print_current_test_name();

        const std::string secret_key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        boost::filesystem::path temp = create_readable_data_file("LoNg TeSt"
                                                                 "\n",
                                                                 ctx().file_buffer_size() * 10, boost::unit_test::framework::current_test_case().p_name);

        auto initial_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        auto partial_key_hash = create_sha256(secret_key, 8);

        DUMP_STR(to_hex(partial_key_hash));

        std::string encrypted_file_marker = partial_key_hash;

        aes_encrypt_file(ctx, temp.generic_string(), secret_key, encrypted_file_marker);

        std::string file_header;
        {
            std::vector<char> header;
            header.resize(encrypted_file_marker.size());

            std::ifstream f(temp.generic_string(), std::ifstream::binary | std::ifstream::out);
            f.read(header.data(), encrypted_file_marker.size());
            auto bytes_read = f.gcount();

            BOOST_REQUIRE_EQUAL(bytes_read, encrypted_file_marker.size());

            f.close();

            file_header.assign(header.data(), header.size());
        }
        BOOST_REQUIRE_EQUAL(file_header, encrypted_file_marker);

        // Check header before decryption attempt!
        auto wrong_partial_key_hash = create_sha256(wrong_key, 8);

        DUMP_STR(to_hex(wrong_partial_key_hash));

        BOOST_REQUIRE_NE(file_header, wrong_partial_key_hash);
        BOOST_REQUIRE_EQUAL(file_header, partial_key_hash);

        aes_decrypt_file(ctx, temp.generic_string(), secret_key, encrypted_file_marker);

        auto last_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        BOOST_REQUIRE_EQUAL(initial_sha256, last_sha256);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_with_saved_tag_and_odd_buffer_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string encrypted_file_marker = "XXX";

        auto& ctx = default_context_with_crypto_api();

        size_t odd_sz = ctx().file_buffer_size() * 10 - 3;
        BOOST_REQUIRE_LT((odd_sz + aes_tag_type {}.size()) % ctx().file_buffer_size(), aes_tag_type {}.size());

        boost::filesystem::path temp = create_readable_data_file("LoNg TeSt"
                                                                 "\n",
                                                                 odd_sz, boost::unit_test::framework::current_test_case().p_name);

        auto initial_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(initial_sha256);

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, true);

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag, true);

        auto last_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(last_sha256);

        BOOST_REQUIRE_EQUAL(initial_sha256, last_sha256);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_decryption_wrong_header_check)
    {
        print_current_test_name();

        const std::string any_key { "Secret Key" };
        const std::string encrypted_file_marker = "XXX";

        auto& ctx = default_context_with_crypto_api();

        size_t odd_sz = ctx().file_buffer_size() * 10 - 3;
        BOOST_REQUIRE_LT((odd_sz + aes_tag_type {}.size()) % ctx().file_buffer_size(), aes_tag_type {}.size());

        boost::filesystem::path temp = create_readable_data_file(encrypted_file_marker,
                                                                 encrypted_file_marker.size(),
                                                                 boost::unit_test::framework::current_test_case().p_name);

        BOOST_REQUIRE_THROW(aes_decrypt_file(ctx, temp.generic_string(), any_key, encrypted_file_marker, {}, false), std::logic_error);

        temp = create_readable_data_file(encrypted_file_marker,
                                         encrypted_file_marker.size() + aes_tag_type {}.size() / 2,
                                         boost::unit_test::framework::current_test_case().p_name);

        BOOST_REQUIRE_THROW(aes_decrypt_file(ctx, temp.generic_string(), any_key, encrypted_file_marker, {}, true), std::logic_error);

        temp = create_readable_data_file("blablabla",
                                         encrypted_file_marker.size() * 10,
                                         boost::unit_test::framework::current_test_case().p_name);

        BOOST_REQUIRE_THROW(aes_decrypt_file(ctx, temp.generic_string(), any_key, encrypted_file_marker, {}, false), std::logic_error);
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
