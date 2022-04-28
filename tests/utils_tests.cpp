#include <boost/endian/conversion.hpp>

#include <ssl_helpers/utils.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(utils_tests)

    BOOST_AUTO_TEST_CASE(time_conversions_check)
    {
        print_current_test_name();

        time_t timestamp_utc = from_iso_string("2018-12-06T10:28:20");

        BOOST_CHECK_EQUAL(timestamp_utc, 1544092100);
        BOOST_CHECK_EQUAL(to_iso_string(timestamp_utc), "2018-12-06T10:28:20");
    }

    BOOST_AUTO_TEST_CASE(little_endian_check)
    {
        print_current_test_name();

#ifdef BOOST_BIG_ENDIAN
        BOOST_REQUIRE(!is_little_endian());
#else
        BOOST_REQUIRE(is_little_endian());
#endif
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
