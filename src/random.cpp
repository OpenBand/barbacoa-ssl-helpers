#include <ssl_helpers/random.h>

#include "ripemd160.h"

#include <openssl/rand.h>

#include <chrono>
#include <memory.h>

namespace ssl_helpers {

uint32_t create_pseudo_random_from_time(const uint32_t offset)
{
    using clock_type = std::chrono::high_resolution_clock;
    auto now = clock_type::now().time_since_epoch().count();

    /// High performance random generator
    /// http://xorshift.di.unimi.it/
    uint64_t r = (uint64_t)now + uint64_t(offset) * 2685821657736338717ULL;
    r ^= (r >> 12);
    r ^= (r << 25);
    r ^= (r >> 27);
    r *= 2685821657736338717ULL;
    return r;
}

std::string create_pseudo_random_string_from_time(const uint32_t offset)
{
    auto r = create_pseudo_random_from_time(offset + 1);
    impl::ripemd160::encoder enc;
    enc.write((const char*)&r, sizeof(r));
    return enc.result().str();
}

uint64_t create_random(const uint64_t offset)
{
    constexpr const size_t SZ = sizeof(uint64_t);

    uint8_t buf[SZ] = { 0 };

    if (offset)
    {
        memcpy(buf, &offset, SZ);
        auto entropy = offset % SZ;
        RAND_add(buf, SZ, entropy);
        memset(buf, 0, SZ);
    }

    if (RAND_bytes(buf, SZ) != 1)
        return 0;

    uint64_t rnd = 0;
    memcpy(&rnd, buf, SZ);
    return rnd;
}
} // namespace ssl_helpers
