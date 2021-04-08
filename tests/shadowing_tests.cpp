#include "tests_common.h"

#include <ssl_helpers/shadowing.h>

#include <functional>

namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(shadowing_tests)

    BOOST_AUTO_TEST_CASE(nxor_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto key_shadow = nxor_encode(key);
        auto key_ = nxor_decode(key_shadow);

        BOOST_CHECK_EQUAL(key, key_);
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
