#include <ssl_helpers/dh.h>
#include <ssl_helpers/encoding.h>
#include <ssl_helpers/random.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(diffie_hellman_tests)

    BOOST_AUTO_TEST_CASE(initialization_check)
    {
        print_current_test_name();

        for (size_t ci = 0; ci < 10; ++ci)
        {
            diffie_hellman dh(default_context_with_crypto_api());

            auto side_public_key = dh.public_key_data();

            DUMP_STR(to_hex(side_public_key));

            BOOST_REQUIRE(dh.initialized());
            BOOST_REQUIRE(!side_public_key.empty());

            auto side_secret = dh.save_private_key_data();

            BOOST_REQUIRE(!side_secret.empty());
        }
    }

    BOOST_AUTO_TEST_CASE(reinitialization_check)
    {
        print_current_test_name();

        diffie_hellman dh(default_context_with_crypto_api(), false);

        BOOST_REQUIRE(!dh.initialized());
        BOOST_REQUIRE_THROW(dh.compute_shared_secret("blablabla"), std::logic_error);

        auto side_public_key = dh.init_side();

        DUMP_STR(to_hex(side_public_key));

        BOOST_REQUIRE(dh.initialized());
        BOOST_REQUIRE(!side_public_key.empty());

        auto side_secret = dh.save_private_key_data();

        DUMP_STR(to_hex(side_secret));

        BOOST_REQUIRE(!side_secret.empty());

        auto side_public_key2 = dh.init_side(side_secret);

        DUMP_STR(to_hex(side_public_key2));

        BOOST_REQUIRE(dh.initialized());
        BOOST_REQUIRE(!side_public_key2.empty());

        BOOST_REQUIRE_EQUAL(to_hex(side_public_key), to_hex(side_public_key2));
    }

    BOOST_AUTO_TEST_CASE(default_handshake_check)
    {
        print_current_test_name();

        diffie_hellman alice_dh(default_context_with_crypto_api());
        diffie_hellman bob_dh(default_context_with_crypto_api());

        BOOST_REQUIRE(alice_dh.initialized());
        BOOST_REQUIRE(bob_dh.initialized());

        auto alice_secret = alice_dh.save_private_key_data();
        auto alice_share = alice_dh.public_key_data();

        DUMP_STR(to_hex(alice_secret));
        DUMP_STR(to_hex(alice_share));

        auto bob_secret = bob_dh.save_private_key_data();
        auto bob_share = bob_dh.public_key_data();

        DUMP_STR(to_hex(bob_secret));
        DUMP_STR(to_hex(bob_share));

        BOOST_REQUIRE_NE(to_hex(alice_share), to_hex(bob_share));

        auto shared_secret1 = alice_dh.compute_shared_secret(bob_share);

        DUMP_STR(to_hex(shared_secret1));

        auto shared_secret2 = bob_dh.compute_shared_secret(alice_share);

        DUMP_STR(to_hex(shared_secret2));

        // Is must be equal
        BOOST_REQUIRE_EQUAL(to_hex(shared_secret1), to_hex(shared_secret2));
    }

    BOOST_AUTO_TEST_CASE(input_check)
    {
        print_current_test_name();

        diffie_hellman dh(default_context_with_crypto_api());

        BOOST_REQUIRE_THROW(dh.compute_shared_secret(""), std::logic_error);

        auto rnd_str = create_pseudo_random_string_from_time();

        DUMP_STR(to_printable(rnd_str));

        BOOST_REQUIRE_THROW(dh.compute_shared_secret(rnd_str), std::logic_error);

        rnd_str = create_random_string(default_context_with_crypto_api(), 1);

        DUMP_STR(to_hex(rnd_str));

        BOOST_REQUIRE_THROW(dh.compute_shared_secret(rnd_str), std::logic_error);

        rnd_str = create_random_string(default_context_with_crypto_api(), 12);

        DUMP_STR(to_printable(rnd_str));

        BOOST_REQUIRE_THROW(dh.compute_shared_secret(rnd_str), std::logic_error);

        rnd_str = create_random_string(default_context_with_crypto_api(), 2 * 1024 * 1024);

        DUMP_STR(to_printable(rnd_str.substr(0, 62)));

        BOOST_REQUIRE_THROW(dh.compute_shared_secret(rnd_str), std::logic_error);
    }

    BOOST_AUTO_TEST_CASE(check_for_different_ec_group_domains_check)
    {
        print_current_test_name();

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_prime256v1));

            DUMP_STR("EC_GROUP_DOMAIN_prime256v1");

            diffie_hellman dh(ctx);

            BOOST_REQUIRE(dh.initialized());

            DUMP_STR(to_printable(dh.public_key_data()));
            DUMP_STR(to_printable(dh.save_private_key_data()));

            BOOST_REQUIRE(!dh.public_key_data().empty());
            BOOST_REQUIRE(!dh.save_private_key_data().empty());
        }

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp256k1));

            DUMP_STR("EC_GROUP_DOMAIN_secp256k1");

            diffie_hellman dh(ctx);

            BOOST_REQUIRE(dh.initialized());

            DUMP_STR(to_printable(dh.public_key_data()));
            DUMP_STR(to_printable(dh.save_private_key_data()));

            BOOST_REQUIRE(!dh.public_key_data().empty());
            BOOST_REQUIRE(!dh.save_private_key_data().empty());
        }

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp384r1));

            DUMP_STR("EC_GROUP_DOMAIN_secp384r1");

            diffie_hellman dh(ctx);

            BOOST_REQUIRE(dh.initialized());

            DUMP_STR(to_printable(dh.public_key_data()));
            DUMP_STR(to_printable(dh.save_private_key_data()));

            BOOST_REQUIRE(!dh.public_key_data().empty());
            BOOST_REQUIRE(!dh.save_private_key_data().empty());
        }

        {
            auto& ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp521r1));

            DUMP_STR("EC_GROUP_DOMAIN_secp521r1");

            diffie_hellman dh(ctx);

            BOOST_REQUIRE(dh.initialized());

            DUMP_STR(to_printable(dh.public_key_data()));
            DUMP_STR(to_printable(dh.save_private_key_data()));

            BOOST_REQUIRE(!dh.public_key_data().empty());
            BOOST_REQUIRE(!dh.save_private_key_data().empty());
        }
    }

    BOOST_AUTO_TEST_CASE(handshake_with_incompatible_ec_group_check)
    {
        print_current_test_name();

        auto& alice_ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_prime256v1));
        diffie_hellman alice_dh(alice_ctx);

        auto& bob_ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp384r1));
        diffie_hellman bob_dh(bob_ctx);

        BOOST_REQUIRE(alice_dh.initialized());
        BOOST_REQUIRE(bob_dh.initialized());

        auto alice_secret = alice_dh.save_private_key_data();
        auto alice_share = alice_dh.public_key_data();

        DUMP_STR(to_hex(alice_secret));
        DUMP_STR(to_hex(alice_share));

        auto bob_secret = bob_dh.save_private_key_data();
        auto bob_share = bob_dh.public_key_data();

        DUMP_STR(to_hex(bob_secret));
        DUMP_STR(to_hex(bob_share));

        BOOST_REQUIRE_NE(to_hex(alice_share), to_hex(bob_share));

        BOOST_REQUIRE_THROW(alice_dh.compute_shared_secret(bob_share), std::logic_error);

        BOOST_REQUIRE_THROW(bob_dh.compute_shared_secret(alice_share), std::logic_error);
    }

    BOOST_AUTO_TEST_CASE(handshake_with_incompatible_ec_group_same_len_check)
    {
        print_current_test_name();

        auto& alice_ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_prime256v1));
        diffie_hellman alice_dh(alice_ctx);

        auto& bob_ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp256k1));
        diffie_hellman bob_dh(bob_ctx);

        BOOST_REQUIRE(alice_dh.initialized());
        BOOST_REQUIRE(bob_dh.initialized());

        auto alice_secret = alice_dh.save_private_key_data();
        auto alice_share = alice_dh.public_key_data();

        DUMP_STR(to_hex(alice_secret));
        DUMP_STR(to_hex(alice_share));

        auto bob_secret = bob_dh.save_private_key_data();
        auto bob_share = bob_dh.public_key_data();

        DUMP_STR(to_hex(bob_secret));
        DUMP_STR(to_hex(bob_share));

        BOOST_REQUIRE_NE(to_hex(alice_share), to_hex(bob_share));

        std::string shared_secret1;
        std::string shared_secret2;
        try
        {
            shared_secret1 = alice_dh.compute_shared_secret(bob_share);

            DUMP_STR(to_hex(shared_secret1));

            shared_secret2 = bob_dh.compute_shared_secret(alice_share);

            DUMP_STR(to_hex(shared_secret2));
        }
        catch (const std::logic_error&)
        {
            // > 0 probability that it could raise error in peer key conversion
        }

        if (!shared_secret1.empty() || !shared_secret2.empty())
        {
            BOOST_REQUIRE_NE(to_hex(shared_secret1), to_hex(shared_secret2));
        }
    }

    BOOST_AUTO_TEST_CASE(most_secure_handshake_check)
    {
        print_current_test_name();

        auto& secure_ctx = context::init(context::configurate().enable_libcrypto_api().set_ec_domain_group(config::EC_GROUP_DOMAIN_secp521r1));

        diffie_hellman alice_dh(secure_ctx);
        diffie_hellman bob_dh(secure_ctx);

        BOOST_REQUIRE(alice_dh.initialized());
        BOOST_REQUIRE(bob_dh.initialized());

        auto alice_secret = alice_dh.save_private_key_data();
        auto alice_share = alice_dh.public_key_data();

        DUMP_STR(to_hex(alice_secret));
        DUMP_STR(to_hex(alice_share));

        auto bob_secret = bob_dh.save_private_key_data();
        auto bob_share = bob_dh.public_key_data();

        DUMP_STR(to_hex(bob_secret));
        DUMP_STR(to_hex(bob_share));

        BOOST_REQUIRE_NE(to_hex(alice_share), to_hex(bob_share));

        auto shared_secret1 = alice_dh.compute_shared_secret(bob_share);

        DUMP_STR(to_hex(shared_secret1));

        auto shared_secret2 = bob_dh.compute_shared_secret(alice_share);

        DUMP_STR(to_hex(shared_secret2));

        // Is must be equal
        BOOST_REQUIRE_EQUAL(to_hex(shared_secret1), to_hex(shared_secret2));
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
