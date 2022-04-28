#include <boost/endian/conversion.hpp>

#include <ssl_helpers/context.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(config_tests)

    BOOST_AUTO_TEST_CASE(switch_config_check)
    {
        print_current_test_name();

        {
            auto& ctx = context::init(context::configurate());

            BOOST_REQUIRE(!ctx().is_enabled_libcrypto_api());
            BOOST_REQUIRE_GT(ctx().file_buffer_size(), 0);
        }

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api());

            BOOST_REQUIRE(ctx().is_enabled_libcrypto_api());
            BOOST_REQUIRE_GT(ctx().file_buffer_size(), 0);
        }

        {
            auto& ctx = context::init(context::configurate().set_file_buffer_size(4 * 1024));

            BOOST_REQUIRE(!ctx().is_enabled_libcrypto_api());
            BOOST_REQUIRE_EQUAL(ctx().file_buffer_size(), 4 * 1024);
        }

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api().set_file_buffer_size(4 * 1024));

            BOOST_REQUIRE(ctx().is_enabled_libcrypto_api());
            BOOST_REQUIRE_EQUAL(ctx().file_buffer_size(), 4 * 1024);
        }
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
