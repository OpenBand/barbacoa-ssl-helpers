#include <functional>

#include <ssl_helpers/random.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


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

        auto rnd1 = create_random(default_context_with_crypto_api());
        auto rnd2 = create_random(default_context_with_crypto_api(), 12);
        auto rnd3 = create_random(default_context_with_crypto_api(), 120);

        // There is extremely low probability that rnd1 = rnd2 or rnd2 = rnd3:

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd1)(rnd2));
        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd2)(rnd3));
    }

    BOOST_AUTO_TEST_CASE(random_fixed_string_check)
    {
        print_current_test_name();

        BOOST_REQUIRE_THROW(create_random_string(default_context_with_crypto_api(), 0, true), std::logic_error);

        auto rnd0 = create_random_string(default_context_with_crypto_api(), 1);

        DUMP_STR(to_printable(rnd0));

        BOOST_REQUIRE_EQUAL(rnd0.size(), 1);

        auto rnd1 = create_random_string(default_context_with_crypto_api(), 13);

        DUMP_STR(to_printable(rnd1));

        BOOST_REQUIRE_EQUAL(rnd1.size(), 13);

        auto rnd2 = create_random_string(default_context_with_crypto_api(), 13, true);

        DUMP_STR(to_printable(rnd2));

        BOOST_REQUIRE_EQUAL(rnd2.size(), 13);

        // There is extremely low probability that rnd1 = rnd2 or rnd2 = rnd3:

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd1)(rnd2));
    }

    BOOST_AUTO_TEST_CASE(random_string_check)
    {
        print_current_test_name();

        BOOST_REQUIRE_THROW(create_random_string(default_context_with_crypto_api(), 1, false), std::logic_error);
        BOOST_REQUIRE_THROW(create_random_string(default_context_with_crypto_api(), 2, false), std::logic_error);

        auto rnd1 = create_random_string(default_context_with_crypto_api(), 13, false);

        DUMP_STR(to_printable(rnd1));

        BOOST_REQUIRE_LE(rnd1.size(), 13);

        auto rnd2 = create_random_string(default_context_with_crypto_api(), 13, false);

        DUMP_STR(to_printable(rnd2));

        BOOST_REQUIRE_LE(rnd2.size(), 13);

        // There is extremely low probability that rnd1 = rnd2 or rnd2 = rnd3:

        BOOST_CHECK_PREDICATE(std::not_equal_to<decltype(rnd1)>(), (rnd1)(rnd2));
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
