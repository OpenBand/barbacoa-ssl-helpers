#include "tests_common.h"

#include <ssl_helpers/random.h>

#include <functional>

namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(random_tests)

    BOOST_AUTO_TEST_CASE(pseudo_random_check)
    {
        print_current_test_name();

        auto rnd1 = create_pseudo_random_from_time();
        auto rnd2 = create_pseudo_random_from_time(12);

        // There is extremely low probability that rnd1 = rnd2 or rnd3 = rnd4:

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd1)(rnd2));

        auto rnd3 = create_pseudo_random_string_from_time();
        auto rnd4 = create_pseudo_random_string_from_time(12);

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd3)>(), (rnd3)(rnd4));
    }

    BOOST_AUTO_TEST_CASE(random_check)
    {
        print_current_test_name();

        auto rnd1 = create_random();
        auto rnd2 = create_random(12);
        auto rnd3 = create_random(120);

        // There is extremely low probability that rnd1 = rnd2 or rnd2 = rnd3:

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd1)(rnd2));
        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd2)(rnd3));
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
