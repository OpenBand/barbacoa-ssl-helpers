#include <functional>

#include <ssl_helpers/shadowing.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(shadowing_tests)

    BOOST_AUTO_TEST_CASE(nxor_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto key_shadow = nxor_encode(key);

        DUMP_STR(to_printable(key_shadow));

        auto key_ = nxor_decode(key_shadow);

        BOOST_CHECK_EQUAL(key, key_);

        DUMP_STR(to_printable(key_));
    }

    BOOST_AUTO_TEST_CASE(nxor_sec_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto key_shadow = nxor_encode_sec(default_context_with_crypto_api(), key);

        DUMP_STR(to_printable(key_shadow));

        auto key_ = nxor_decode(key_shadow);

        BOOST_CHECK_EQUAL(key, key_);

        DUMP_STR(to_printable(key_));
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
