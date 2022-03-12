#pragma once

#include <string>
#include <functional>
#include <memory>

#include <ssl_helpers/context.h>


namespace ssl_helpers {

class diffie_hellman
{
public:
    diffie_hellman(const context&,
                   bool init_side = true);

    bool initialized() const
    {
        return !_secret_data.empty();
    }

    // Generate private key and return site public key (peer for other).
    std::string init_side();

    // Load private key and return site public key (peer for other).
    std::string init_side(const std::string& private_key_data);

    const std::string& public_key_data() const
    {
        return _public_data;
    }

    // Return raw shared secret.
    // Warning:
    //     Never use a derived secret directly. Typically it is passed
    //     through some hash function to produce a key.
    //     Ensure that the peer uses the same EC_GROUP_DOMAIN
    std::string compute_shared_secret(const std::string& peer_public_key_data);

    // Save private key to have ability to restore with init_side
    // Warning:
    //     This call return only key data. Enshure that the
    //     same EC_GROUP_DOMAIN is used for init_side. Or
    //     store EC_GROUP_DOMAIN youself
    std::string save_private_key_data() const;

private:
    const context& _ctx;
    int _ec_considered_curve_nid = -1;
    std::string _secret_data;
    std::string _public_data;
};

} // namespace ssl_helpers
