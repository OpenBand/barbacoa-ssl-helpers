#include "tests_common.h"

#include <ssl_helpers/crypto.h>
#include <ssl_helpers/hash.h>
#include <ssl_helpers/encoding.h>

#include <functional>
#include <sstream>

#include <boost/filesystem.hpp>

namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(crypto_tests)

    BOOST_AUTO_TEST_CASE(basic_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        std::string data;
        for (size_t ci = 0; ci < 10; ++ci)
        {
            data.append(create_test_data());
        }

        BOOST_REQUIRE(!data.empty());
        BOOST_REQUIRE_GT(data.size(), 16);

        auto cipher_data = aes_encrypt(key, data);

        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(key, cipher_data);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(basic_small_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());
        BOOST_REQUIRE_LT(data.size(), 16);

        auto cipher_data = aes_encrypt(key, data);

        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(key, cipher_data);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(basic_encryption_with_tag_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        std::string data;
        for (size_t ci = 0; ci < 10; ++ci)
        {
            data.append(create_test_data());
        }

        BOOST_REQUIRE(!data.empty());
        BOOST_REQUIRE_GT(data.size(), 16);

        auto create_check_tag = [](const std::string& key, const std::string& cipher_data) {
            std::string ss;
            ss.reserve(key.size() + cipher_data.size());

            ss.append(key);
            ss.append(cipher_data);

            return create_ripemd160(ss);
        };

        std::string tag;
        auto cipher_data = aes_encrypt(key, data, create_check_tag, tag);

        BOOST_REQUIRE(!tag.empty());
        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(key, cipher_data, tag, create_check_tag);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        std::string data;
        for (size_t ci = 0; ci < 200; ++ci)
        {
            data.append(create_test_data());
        }

        constexpr size_t chunk_size = 512;

        BOOST_REQUIRE(!data.empty());
        BOOST_REQUIRE_GT(data.size(), chunk_size * 2);

        const std::string ADD_MARK { "AAA" };
        std::string ciphertext_stream_data;
        {
            std::stringstream source_ss { data };
            std::stringstream encryption_ss;

            aes_encryption_stream stream { key, ADD_MARK };

            //write ADD = "AAA" at the beginning
            encryption_ss << stream.start();

            //encryption cycle
            char buff[chunk_size];
            for (std::streamsize bytes_read = 1; source_ss.read(buff, sizeof(buff)) || bytes_read > 0;)
            {
                bytes_read = source_ss.gcount();
                if (bytes_read > 0)
                {
                    encryption_ss << stream.encrypt({ buff, static_cast<uint32_t>(bytes_read) });
                }
            }

            //write tag at the end
            encryption_ss << aes_to_string(stream.finalize());

            ciphertext_stream_data = encryption_ss.str();
        }

        BOOST_REQUIRE(!ciphertext_stream_data.empty());

        std::string planetext_stream_data;
        {
            std::stringstream source_ss { ciphertext_stream_data };
            std::stringstream encryption_ss;

            char buff[chunk_size];

            //read mark
            source_ss.read(buff, ADD_MARK.size());
            buff[ADD_MARK.size()] = 0;
            BOOST_REQUIRE_EQUAL(std::string { buff }, ADD_MARK);

            aes_decryption_stream stream { key, ADD_MARK };

            stream.start();

            aes_tag_type tag;

            //decryption cycle
            size_t cypher_size = 0;
            for (std::streamsize bytes_read = 1; source_ss.read(buff, sizeof(buff)) || bytes_read > 0;)
            {
                bytes_read = source_ss.gcount();
                if (bytes_read > 0)
                {
                    if (cypher_size + bytes_read <= data.size())
                    {
                        encryption_ss << stream.decrypt({ buff, static_cast<uint32_t>(bytes_read) });
                        cypher_size += bytes_read;
                    }
                    else
                    {
                        size_t rest = 0;
                        if (cypher_size < data.size())
                        {
                            rest = data.size() - cypher_size;
                            encryption_ss << stream.decrypt({ buff, rest });
                            cypher_size = data.size();
                        }

                        std::memcpy(tag.data(), buff + rest, std::min(bytes_read - rest, tag.size()));
                    }
                }
            }

            BOOST_REQUIRE_NO_THROW(stream.finalize(tag));

            planetext_stream_data = encryption_ss.str();
        }

        BOOST_REQUIRE(!planetext_stream_data.empty());

        BOOST_REQUIRE_EQUAL(data, planetext_stream_data);
    }

    BOOST_AUTO_TEST_CASE(stream_small_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream;
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        std::string data_;

        aes_decryption_stream dec_stream;
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_NO_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))));

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_small_encryption_with_add_check)
    {
        print_current_test_name();

        std::string add_mark { "(a)" };
        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream;
        enc_stream.start(key, add_mark);
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        std::string data_;

        aes_decryption_stream dec_stream;
        dec_stream.start(key, add_mark);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_NO_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))));

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_data_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream;
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        //corrupt
        ciphertext_stream_data[data.size() / 2] = ~ciphertext_stream_data[data.size() / 2];

        std::string data_;

        aes_decryption_stream dec_stream;
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_tag_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream;
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        //corrupt
        ciphertext_stream_data[data.size() + 8] = ~ciphertext_stream_data[data.size() + 8];

        std::string data_;

        aes_decryption_stream dec_stream;
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);

        //failed finalization but data correct
        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_add_encryption_check)
    {
        print_current_test_name();

        std::string add_mark { "(a)" };
        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream;
        enc_stream.start(key, add_mark);
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        //corrupt
        add_mark[add_mark.size() / 2] = ~add_mark[add_mark.size() / 2];

        std::string data_;

        aes_decryption_stream dec_stream;
        dec_stream.start(key, add_mark);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);

        //failed finalization but data correct
        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(salted_key_check)
    {
        print_current_test_name();

        const std::string key { "Simple Key" };
        auto data = create_test_data();

        std::vector<std::string> cipher_key_history;
        std::vector<std::string> salt_history;

        const size_t times = 3;

        for (size_t ci = 0; ci < times; ++ci)
        {
            auto key_data = aes_create_salted_key(key);

            std::string cipher_key = key_data.first;
            std::string salt = to_base64(aes_to_string(key_data.second)); //pass or save separately from key

            DUMP_STR(to_base64(cipher_key));
            DUMP_STR(salt);

            auto cipher_data = aes_encrypt(cipher_key, data);

            BOOST_REQUIRE(!cipher_data.empty());

            auto data_ = aes_decrypt(aes_get_salted_key(key, from_base64(salt)), cipher_data);

            BOOST_REQUIRE(!data_.empty());

            BOOST_REQUIRE_EQUAL(data, data_);

            cipher_key_history.emplace_back(std::string(to_base64(cipher_key)));
            salt_history.emplace_back(std::move(salt));
        }

        for (size_t ci = 1; ci < times; ++ci)
        {
            BOOST_CHECK_NE(cipher_key_history[ci - 1], cipher_key_history[ci]);
            BOOST_CHECK_NE(salt_history[ci - 1], salt_history[ci]);
        }
    }

    BOOST_AUTO_TEST_CASE(stream_multysession_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        auto data = create_test_data();

        BOOST_REQUIRE(!data.empty());

        auto store_chunk = [](std::stringstream& ss, const std::string& chunk) {
            size_t sz = chunk.size();
            //there is more compact way to store digital value but this simple way used for test
            ss.write((char*)&sz, sizeof(sz));
            ss << chunk;
        };
        auto read_chunk = [](std::stringstream& ss) {
            size_t sz = 0;
            ss.read((char*)&sz, sizeof(sz));
            std::vector<char> result(sz);
            ss.read(result.data(), sz);
            return std::string(result.data(), result.size());
        };

        std::string payload;
        std::stringstream encryption_ss;
        aes_encryption_stream enc(key, "x");

        store_chunk(encryption_ss, enc.start());
        store_chunk(encryption_ss, enc.encrypt(data + "1"));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(data + "1");

        store_chunk(encryption_ss, enc.start());
        store_chunk(encryption_ss, enc.encrypt(data + data + "2"));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(data + data + "2");

        const std::string new_key { "New Key Only For One Next Session" };

        store_chunk(encryption_ss, enc.start(new_key));
        store_chunk(encryption_ss, enc.encrypt(data + data + "3"));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(data + data + "3");

        //restore previous key but use new ADD
        store_chunk(encryption_ss, enc.start({}, "x2"));
        store_chunk(encryption_ss, enc.encrypt(data + "4"));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(data + "4");

        DUMP_STR(to_base64(encryption_ss.str()));

        std::string payload_;
        aes_decryption_stream dec(key, "x");

        dec.start({}, read_chunk(encryption_ss));
        payload_.append(dec.decrypt(read_chunk(encryption_ss)));
        BOOST_REQUIRE_NO_THROW(dec.finalize(aes_from_string(read_chunk(encryption_ss))));

        dec.start({}, read_chunk(encryption_ss));
        payload_.append(dec.decrypt(read_chunk(encryption_ss)));
        BOOST_REQUIRE_NO_THROW(dec.finalize(aes_from_string(read_chunk(encryption_ss))));

        dec.start(new_key, read_chunk(encryption_ss));
        payload_.append(dec.decrypt(read_chunk(encryption_ss)));
        BOOST_REQUIRE_NO_THROW(dec.finalize(aes_from_string(read_chunk(encryption_ss))));

        dec.start({}, read_chunk(encryption_ss));
        payload_.append(dec.decrypt(read_chunk(encryption_ss)));
        BOOST_REQUIRE_NO_THROW(dec.finalize(aes_from_string(read_chunk(encryption_ss))));

        BOOST_REQUIRE_EQUAL(payload, payload_);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        boost::filesystem::path temp = create_readable_data_file(100 * 1024, boost::unit_test::framework::current_test_case().p_name);

        auto tag = aes_encrypt_file(temp.generic_string(), key, "XXX");

        aes_decrypt_file(temp.generic_string(), key, tag, "XXX");

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(flip_flap_with_marker_check)
    {
        print_current_test_name();

        std::string data;
        for (size_t ci = 0; ci < 50; ++ci)
        {
            data.append(create_test_data());
        }

        DUMP_STR(to_printable(data));

        const std::string key { "Temp Key" };
        const std::string marker { "%%" };

        auto flip_data = aes_ecnrypt_flip(data, key, marker, true); //flip

        const auto& session_data = flip_data.second;

        DUMP_STR(to_printable(session_data)); //flip data

        const auto& cipher_data = flip_data.first;

        DUMP_STR(to_printable(cipher_data)); //flap data

        auto data_ = aes_decrypt_flip(cipher_data, key, session_data, marker); //flap

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(flip_flap_check)
    {
        print_current_test_name();

        std::string data;
        for (size_t ci = 0; ci < 10; ++ci)
        {
            data.append(create_test_data());
        }

        DUMP_STR(to_printable(data));

        const std::string base_key { "Temp Key" };

        for (size_t ci = 0; ci < 5; ++ci)
        {
            std::string key = base_key + std::to_string(ci + 1);

            auto flip_data = aes_ecnrypt_flip(data, key, {}, true); //flip

            const auto& session_data = flip_data.second;

            DUMP_STR(to_printable(session_data)); //flip data

            const auto& cipher_data = flip_data.first;

            DUMP_STR(to_printable(cipher_data)); //flap data

            auto data_ = aes_decrypt_flip(cipher_data, key, session_data); //flap

            BOOST_REQUIRE_EQUAL(data, data_);
        }
    }

    BOOST_AUTO_TEST_CASE(simplest_flip_flap_check)
    {
        print_current_test_name();

        std::string data;
        for (size_t ci = 0; ci < 10; ++ci)
        {
            data.append(create_test_data());
        }

        DUMP_STR(to_printable(data));

        const std::string key { "Temp Key3" };

        for (size_t ci = 0; ci < 5; ++ci)
        {
            auto flip_data = aes_ecnrypt_flip(data, key); //flip

            const auto& session_data = flip_data.second;

            DUMP_STR(to_printable(session_data)); //flip data

            const auto& cipher_data = flip_data.first;

            DUMP_STR(to_printable(cipher_data)); //flap data

            auto data_ = aes_decrypt_flip(cipher_data, key, session_data); //flap

            BOOST_REQUIRE_EQUAL(data, data_);
        }
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
