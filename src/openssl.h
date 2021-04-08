#pragma once

#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

namespace ssl_helpers {
namespace impl {

    int init_openssl();

} // namespace impl
} // namespace ssl_helpers
