#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <ssl_helpers/dh.h>

#include <ssl_helpers/shadowing.h>

#include "ssl_helpers_defines.h"


namespace ssl_helpers {
namespace {

    int ec_considered_curve_nid_from_group_domain(const config::EC_GROUP_DOMAIN group_domain)
    {
        switch (group_domain)
        {
        case config::EC_GROUP_DOMAIN_prime256v1:
            return NID_X9_62_prime256v1;
        case config::EC_GROUP_DOMAIN_secp256k1:
            return NID_secp256k1;
        case config::EC_GROUP_DOMAIN_secp384r1:
            return NID_secp384r1;
        case config::EC_GROUP_DOMAIN_secp521r1:
            return NID_secp521r1;
        default:
            SSL_HELPERS_ERROR("Invalid EC Group Domain");
            return -1;
        }
    }

    // It depends on EC Group Domain
    static const size_t MAX_POINT_UNCOMPRESSED_SIZE = 256;

    std::string serialize_evp_key_to_curve_order(EVP_PKEY* pkey)
    {
        SSL_HELPERS_ASSERT(pkey != NULL, "Invalid input key");

        // ..._get0 - doesn't allocate memory
        const EC_KEY* pkey_impl = EVP_PKEY_get0_EC_KEY(pkey);
        SSL_HELPERS_ASSERT(pkey_impl != NULL, "EVP_PKEY_get0_EC_KEY() failed");

        const BIGNUM* pkey_prv = EC_KEY_get0_private_key(pkey_impl);
        SSL_HELPERS_ASSERT(pkey_prv != NULL, "EC_KEY_get0_private_key() failed");

        std::string buff;
        buff.resize(BN_num_bytes(pkey_prv));

        BN_bn2bin(pkey_prv, (unsigned char*)(buff.data()));

        return buff;
    }

    void deserialize_evp_key_from_curve_order(const int ec_considered_curve_nid,
                                              const std::string& data,
                                              EVP_PKEY*& pkey)
    {
        SSL_HELPERS_ASSERT(pkey == NULL, "Key must be marked as uninitialized");

        BIGNUM* prv = NULL;
        EC_KEY* pkey_impl = NULL;
        EC_POINT* pub = NULL;

        auto clean_up = [&]() {
            if (pub)
            {
                EC_POINT_free(pub);
            }
            if (prv)
            {
                BN_free(prv);
            }
            if (pkey_impl)
            {
                EC_KEY_free(pkey_impl);
            }
        };
        try
        {
            auto new_evp_key_result = (NULL != (pkey = EVP_PKEY_new()));
            SSL_HELPERS_ASSERT(new_evp_key_result, ERR_error_string(ERR_get_error(), nullptr));

            prv = BN_bin2bn((const unsigned char*)data.data(), (int)data.size(), NULL);
            SSL_HELPERS_ASSERT(prv != NULL, "BN_bin2bn() failed");

            auto new_ec_key_impl_result = (NULL != (pkey_impl = EC_KEY_new_by_curve_name(ec_considered_curve_nid)));
            SSL_HELPERS_ASSERT(new_ec_key_impl_result, ERR_error_string(ERR_get_error(), nullptr));

            const EC_GROUP* pgroup = EC_KEY_get0_group(pkey_impl);
            SSL_HELPERS_ASSERT(pgroup != NULL, "EC_KEY_get0_group() failed");

            auto ev_key_set_private_key_result = (1 == EC_KEY_set_private_key(pkey_impl, prv));
            SSL_HELPERS_ASSERT(ev_key_set_private_key_result, ERR_error_string(ERR_get_error(), nullptr));

            auto new_ec_point_result = (NULL != (pub = EC_POINT_new(pgroup)));
            SSL_HELPERS_ASSERT(new_ec_point_result, ERR_error_string(ERR_get_error(), nullptr));

            // We must calculate public key directly
            auto ec_point_mul_result = (1 == EC_POINT_mul(pgroup, pub, prv, NULL, NULL, NULL));
            SSL_HELPERS_ASSERT(ec_point_mul_result, ERR_error_string(ERR_get_error(), nullptr));

            auto ev_key_set_public_key_result = (1 == EC_KEY_set_public_key(pkey_impl, pub));
            SSL_HELPERS_ASSERT(ev_key_set_public_key_result, ERR_error_string(ERR_get_error(), nullptr));

            auto copy_to_evp_key_result = (1 == EVP_PKEY_set1_EC_KEY(pkey, pkey_impl));
            SSL_HELPERS_ASSERT(copy_to_evp_key_result, ERR_error_string(ERR_get_error(), nullptr));

            clean_up();
        }
        catch (std::exception& e)
        {
            clean_up();

            throw;
        }
    }

    std::string serialize_evp_key_to_public_key_octets(EVP_PKEY* pkey)
    {
        SSL_HELPERS_ASSERT(pkey != NULL, "Invalid input key");

        const EC_KEY* pkey_impl = EVP_PKEY_get0_EC_KEY(pkey);
        SSL_HELPERS_ASSERT(pkey_impl != NULL, "EVP_PKEY_get0_EC_KEY() failed");

        const EC_GROUP* pgroup = EC_KEY_get0_group(pkey_impl);
        SSL_HELPERS_ASSERT(pgroup != NULL, "EC_KEY_get0_group() failed");

        const EC_POINT* pkey_pub = EC_KEY_get0_public_key(pkey_impl);
        SSL_HELPERS_ASSERT(pkey_pub != NULL, "EC_KEY_get0_public_key() failed");

        size_t octets_len = MAX_POINT_UNCOMPRESSED_SIZE;
        unsigned char octets[MAX_POINT_UNCOMPRESSED_SIZE];

        octets_len = EC_POINT_point2oct(pgroup, pkey_pub,
                                        POINT_CONVERSION_COMPRESSED,
                                        octets, octets_len, NULL);
        SSL_HELPERS_ASSERT(octets_len > 0 && octets_len <= MAX_POINT_UNCOMPRESSED_SIZE, "EC_POINT_point2oct() failed");

        std::string buff(reinterpret_cast<const char*>(octets), octets_len);
        return buff;
    }

    void deserialize_evp_key_from_public_key_octets(const int ec_considered_curve_nid,
                                                    const std::string& data,
                                                    EVP_PKEY*& pkey)
    {
        SSL_HELPERS_ASSERT(pkey == NULL, "Key must be marked as uninitialized");

        EC_KEY* pkey_impl = NULL;
        EC_POINT* pub = NULL;

        auto clean_up = [&]() {
            if (pub)
            {
                EC_POINT_free(pub);
            }
            if (pkey_impl)
            {
                EC_KEY_free(pkey_impl);
            }
        };
        try
        {
            auto new_evp_key_result = (NULL != (pkey = EVP_PKEY_new()));
            SSL_HELPERS_ASSERT(new_evp_key_result, ERR_error_string(ERR_get_error(), nullptr));

            auto new_ec_key_impl_result = (NULL != (pkey_impl = EC_KEY_new_by_curve_name(ec_considered_curve_nid)));
            SSL_HELPERS_ASSERT(new_ec_key_impl_result, ERR_error_string(ERR_get_error(), nullptr));

            const EC_GROUP* pgroup = EC_KEY_get0_group(pkey_impl);
            SSL_HELPERS_ASSERT(pgroup != NULL, "EC_KEY_get0_group() failed");

            auto new_ec_point_result = (NULL != (pub = EC_POINT_new(pgroup)));
            SSL_HELPERS_ASSERT(new_ec_point_result, ERR_error_string(ERR_get_error(), nullptr));

            auto ec_point_decode_result = (1 == EC_POINT_oct2point(pgroup, pub, (const unsigned char*)data.data(), (int)data.size(), NULL));
            SSL_HELPERS_ASSERT(ec_point_decode_result, ERR_error_string(ERR_get_error(), nullptr));

            auto ev_key_set_public_key_result = (1 == EC_KEY_set_public_key(pkey_impl, pub));
            SSL_HELPERS_ASSERT(ev_key_set_public_key_result, ERR_error_string(ERR_get_error(), nullptr));

            auto copy_to_evp_key_result = (1 == EVP_PKEY_set1_EC_KEY(pkey, pkey_impl));
            SSL_HELPERS_ASSERT(copy_to_evp_key_result, ERR_error_string(ERR_get_error(), nullptr));

            clean_up();
        }
        catch (std::exception& e)
        {
            clean_up();

            throw;
        }
    }
} // namespace

diffie_hellman::diffie_hellman(const context& ctx,
                               bool init_side_)
    : _ctx(ctx)
{
    SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");
    _ec_considered_curve_nid = ec_considered_curve_nid_from_group_domain(ctx().ec_domain_group());

    if (init_side_)
        init_side();
}

std::string diffie_hellman::init_side()
{
    EVP_PKEY_CTX *params_ctx = NULL, *pkey_ctx = NULL;
    EVP_PKEY *params = NULL, *pkey = NULL;

    auto clean_up = [&]() {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
        if (pkey_ctx)
        {
            EVP_PKEY_CTX_free(pkey_ctx);
        }
        if (params)
        {
            EVP_PKEY_free(params);
        }
        if (params_ctx)
        {
            EVP_PKEY_CTX_free(params_ctx);
        }
    };

    try
    {
        auto new_params_ctx_result = (NULL != (params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)));
        SSL_HELPERS_ASSERT(new_params_ctx_result, ERR_error_string(ERR_get_error(), nullptr));

        // Initialise the parameter generation
        auto paramgen_init_result = (1 == EVP_PKEY_paramgen_init(params_ctx));
        SSL_HELPERS_ASSERT(paramgen_init_result, ERR_error_string(ERR_get_error(), nullptr));

        auto set_ec_paramgen_curve_nid_result = (1 == EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, _ec_considered_curve_nid));
        SSL_HELPERS_ASSERT(set_ec_paramgen_curve_nid_result, ERR_error_string(ERR_get_error(), nullptr));

        // Create the parameter object params
        auto paramgen_result = EVP_PKEY_paramgen(params_ctx, &params);
        SSL_HELPERS_ASSERT(paramgen_result, ERR_error_string(ERR_get_error(), nullptr));

        // Create the context for the secret key generation with given params
        auto new_key_ctx_result = (NULL != (pkey_ctx = EVP_PKEY_CTX_new(params, NULL)));
        SSL_HELPERS_ASSERT(new_key_ctx_result, ERR_error_string(ERR_get_error(), nullptr));

        // Generate the secret key
        auto keygen_init_result = (1 == EVP_PKEY_keygen_init(pkey_ctx));
        SSL_HELPERS_ASSERT(keygen_init_result, ERR_error_string(ERR_get_error(), nullptr));

        auto keygen_result = (1 == EVP_PKEY_keygen(pkey_ctx, &pkey));
        SSL_HELPERS_ASSERT(keygen_result, ERR_error_string(ERR_get_error(), nullptr));

        // Store key data
        _secret_data = nxor_encode_sec(_ctx, serialize_evp_key_to_curve_order(pkey));
        _public_data = serialize_evp_key_to_public_key_octets(pkey);

        clean_up();

        return _public_data;
    }
    catch (std::exception& e)
    {
        clean_up();

        throw;
    }

    return {};
}

std::string diffie_hellman::init_side(const std::string& private_key_data)
{
    SSL_HELPERS_ASSERT(!private_key_data.empty(), "Key data required");

    EVP_PKEY* pkey = NULL;

    auto clean_up = [&]() {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
    };

    try
    {
        deserialize_evp_key_from_curve_order(_ec_considered_curve_nid, private_key_data, pkey);

        // Store key data
        _secret_data = nxor_encode_sec(_ctx, private_key_data);
        _public_data = serialize_evp_key_to_public_key_octets(pkey);

        clean_up();

        return _public_data;
    }
    catch (std::exception& e)
    {
        clean_up();

        throw;
    }
    return {};
}

std::string diffie_hellman::compute_shared_secret(const std::string& peer_public_key_data)
{
    SSL_HELPERS_ASSERT(!peer_public_key_data.empty(), "Peer public key data required");
    SSL_HELPERS_ASSERT(initialized(), "Not initialized");

    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    EVP_PKEY_CTX* pderive_ctx = NULL;
    void* psecret_buff = nullptr;

    auto clean_up = [&]() {
        if (psecret_buff)
        {
            OPENSSL_free(psecret_buff);
        }
        if (pderive_ctx)
        {
            EVP_PKEY_CTX_free(pderive_ctx);
        }
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
        if (peerkey)
        {
            EVP_PKEY_free(peerkey);
        }
    };
    try
    {
        deserialize_evp_key_from_public_key_octets(_ec_considered_curve_nid, peer_public_key_data, peerkey);

        deserialize_evp_key_from_curve_order(_ec_considered_curve_nid, save_private_key_data(), pkey);

        // Create the context for the shared secret derivation
        auto new_derivation_ctx_result = (NULL != (pderive_ctx = EVP_PKEY_CTX_new(pkey, NULL)));
        SSL_HELPERS_ASSERT(new_derivation_ctx_result, ERR_error_string(ERR_get_error(), nullptr));

        auto derivation_init_result = (1 == EVP_PKEY_derive_init(pderive_ctx));
        SSL_HELPERS_ASSERT(derivation_init_result, ERR_error_string(ERR_get_error(), nullptr));

        // Provide the peer public key
        auto derivation_set_peer_result = (1 == EVP_PKEY_derive_set_peer(pderive_ctx, peerkey));
        SSL_HELPERS_ASSERT(derivation_set_peer_result, ERR_error_string(ERR_get_error(), nullptr));

        // Determine buffer length for shared secret
        size_t secret_len = 0;
        auto derivation_result = (1 == (EVP_PKEY_derive(pderive_ctx, NULL, &secret_len)));
        SSL_HELPERS_ASSERT(derivation_result, ERR_error_string(ERR_get_error(), nullptr));

        // Create the buffer
        auto openssl_malloc_result = (NULL != (psecret_buff = OPENSSL_malloc(secret_len)));
        SSL_HELPERS_ASSERT(openssl_malloc_result, ERR_error_string(ERR_get_error(), nullptr));

        // Derive the shared secret
        derivation_result = (1 == (EVP_PKEY_derive(pderive_ctx, (unsigned char*)psecret_buff, &secret_len)));
        SSL_HELPERS_ASSERT(derivation_result, ERR_error_string(ERR_get_error(), nullptr));

        std::string shared(reinterpret_cast<const char*>(psecret_buff), secret_len);

        clean_up();

        return shared;
    }
    catch (std::exception& e)
    {
        clean_up();

        throw;
    }
    return {};
}

std::string diffie_hellman::save_private_key_data() const
{
    SSL_HELPERS_ASSERT(initialized(), "Not initialized");

    return nxor_decode(_secret_data);
}

} // namespace ssl_helpers
