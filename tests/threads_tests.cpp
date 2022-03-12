#include <thread>
#include <vector>
#include <memory>

#include <ssl_helpers/crypto.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(threads_tests)

    BOOST_AUTO_TEST_CASE(map_blocks_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        // Make data with odd size (only stream encryption will support this)

        std::string data = create_test_data(1024 * 123 + 3);

        const size_t threads_amount = 4;

        BOOST_REQUIRE_GT(threads_amount, 1);

        std::vector<std::unique_ptr<std::thread>> threads;

        size_t block_next = 0;
        size_t block_sz = data.size() / threads_amount;
        std::vector<std::string> data_map;
        std::vector<aes_tag_type> encrypted_tag_map;

        threads.resize(threads_amount);

        auto& ssl_ctx = default_context_with_crypto_api();

        // Map

        data_map.resize(threads_amount);
        encrypted_tag_map.resize(threads_amount);

        for (size_t thread_idx = 0; thread_idx < threads_amount; ++thread_idx)
        {
            if (thread_idx + 1 == threads_amount)
                block_sz = data.size() - block_sz * (threads_amount - 1);

            data_map[thread_idx] = data.substr(block_next, block_sz);

            block_next += block_sz;
        }

        for (size_t thread_idx = 0; thread_idx < threads_amount; ++thread_idx)
        {
            threads[thread_idx].reset(new std::thread([thread_idx, key,
                                                       &data_map, &encrypted_tag_map,
                                                       &ssl_ctx]() {
                aes_encryption_stream ss(ssl_ctx);
                ss.start(key);
                auto encrypted = ss.encrypt(data_map[thread_idx]);

                BOOST_REQUIRE_EQUAL(encrypted.size(), data_map[thread_idx].size());

                data_map[thread_idx] = encrypted;
                encrypted_tag_map[thread_idx] = ss.finalize();
            }));
        }

        for (auto&& pthread : threads)
        {
            pthread->join();
        }

        // Reduce

        for (size_t thread_idx = 0; thread_idx < threads_amount; ++thread_idx)
        {
            threads[thread_idx].reset(new std::thread([thread_idx, key,
                                                       &data_map, &encrypted_tag_map,
                                                       &ssl_ctx]() {
                aes_decryption_stream ss(ssl_ctx);
                ss.start(key);

                data_map[thread_idx] = ss.decrypt(data_map[thread_idx]);

                ss.finalize(encrypted_tag_map[thread_idx]);
            }));
        }

        for (auto&& pthread : threads)
        {
            pthread->join();
        }

        encrypted_tag_map.clear();

        std::string data_;
        for (auto&& data_chunk : data_map)
        {
            data_.append(data_chunk);
        }

        BOOST_REQUIRE_EQUAL(data.size(), data_.size());
        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
