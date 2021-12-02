#include <ssl_helpers/encoding.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(encoding_tests)

    BOOST_AUTO_TEST_CASE(hex_check)
    {
        print_current_test_name();

        auto data = create_test_data();

        auto hex_data = to_hex(data);

        DUMP_STR(hex_data);

        BOOST_CHECK_EQUAL(hex_data, "7465737401020074657374");

        BOOST_CHECK_EQUAL(from_hex(hex_data), data);
    }

    BOOST_AUTO_TEST_CASE(base58_check)
    {
        print_current_test_name();

        auto data = create_test_data();

        auto base58_data = to_base58(data);

        DUMP_STR(base58_data);

        BOOST_CHECK_EQUAL(base58_data, "Vs5LyQWRVPGQB4P");

        BOOST_CHECK_EQUAL(from_base58(base58_data), data);
    }

    BOOST_AUTO_TEST_CASE(base64_check)
    {
        print_current_test_name();

        std::string data = "{\r\n"
                           "\t\"Resources\":\r\n"
                           "\t{\r\n"
                           "\t\t\"gold\": 34,\r\n"
                           "\t\t\"water\": 50\r\n"
                           "\t}\r\n"
                           "}";

        auto base64_data = to_base64(data);

        DUMP_STR(base64_data);

        BOOST_CHECK_EQUAL(base64_data, "ew0KCSJSZXNvdXJjZXMiOg0KCXsNCgkJImdvbGQiOiAzNCwNCgkJIndhdGVyIjogNTANCgl9DQp9");

        BOOST_CHECK_EQUAL(from_base64(base64_data), data);
    }

    BOOST_AUTO_TEST_CASE(printable_check)
    {
        print_current_test_name();

        std::string data("\x00Hi", 3);

        BOOST_CHECK_EQUAL(to_printable(data), std::string(".Hi"));

        data = std::string("1\x03\x03\x03\\23", 6);

        BOOST_CHECK_EQUAL(to_printable(data), std::string("1...\\2"));

        BOOST_CHECK_EQUAL(to_printable(data, '*'), std::string("1***\\2"));

        BOOST_CHECK_EQUAL(to_printable(data, '*', "\\"), std::string("1****2"));

        data = std::string("Hi\t!\n");

        BOOST_CHECK_EQUAL(to_printable(data, '.'), std::string("Hi.!."));

        BOOST_CHECK_EQUAL(to_printable(data, '.', {}), std::string("Hi\t!\n"));
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
