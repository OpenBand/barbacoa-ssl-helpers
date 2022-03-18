#include <boost/filesystem.hpp>

#include <ssl_helpers/crypto.h>
#include <ssl_helpers/hash.h>
#include <ssl_helpers/encoding.h>

#include "tests_common.h"


namespace ssl_helpers {
namespace tests {

    BOOST_AUTO_TEST_SUITE(crypto_tests)

    BOOST_AUTO_TEST_CASE(basic_encryption_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        auto cipher_data = aes_encrypt(default_context_with_crypto_api(), data, key);

        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(default_context_with_crypto_api(), cipher_data, key);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(basic_small_encryption_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        auto cipher_data = aes_encrypt(default_context_with_crypto_api(), data, key);

        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(default_context_with_crypto_api(), cipher_data, key);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(basic_odd_encryption_check)
    {
        print_current_test_name();

        const size_t odd_sz = 123;

        std::string data = create_test_data(odd_sz);

        BOOST_REQUIRE_EQUAL(data.size(), odd_sz);

        const std::string key { "Secret Key" };

        auto cipher_data = aes_encrypt(default_context_with_crypto_api(), data, key);

        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(default_context_with_crypto_api(), cipher_data, key);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(basic_encryption_with_tag_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        auto create_check_tag = [](const std::string& key, const std::string& cipher_data) {
            std::string ss;
            ss.reserve(key.size() + cipher_data.size());

            ss.append(key);
            ss.append(cipher_data);

            return create_ripemd160(ss);
        };

        std::string tag;
        auto cipher_data = aes_encrypt(default_context_with_crypto_api(), data, key, create_check_tag, tag);

        BOOST_REQUIRE(!tag.empty());
        BOOST_REQUIRE(!cipher_data.empty());

        auto data_ = aes_decrypt(default_context_with_crypto_api(), cipher_data, key, tag, create_check_tag);

        BOOST_REQUIRE(!data_.empty());

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_encryption_check)
    {
        print_current_test_name();

        constexpr size_t chunk_size = 256;

        std::string data = create_test_data(chunk_size * 3);

        const std::string key { "Secret Key" };

        const std::string ADD_MARK { "AAA" };
        std::string ciphertext_stream_data;
        {
            std::stringstream source_ss { data };
            std::stringstream encryption_ss;

            aes_encryption_stream stream { default_context_with_crypto_api(), key, ADD_MARK };

            // Write ADD = "AAA" at the beginning
            encryption_ss << stream.start();

            // Encryption cycle
            char buff[chunk_size];
            for (std::streamsize bytes_read = 1; source_ss.read(buff, sizeof(buff)) || bytes_read > 0;)
            {
                bytes_read = source_ss.gcount();
                if (bytes_read > 0)
                {
                    encryption_ss << stream.encrypt({ buff, static_cast<uint32_t>(bytes_read) });
                }
            }

            // Write tag at the end
            encryption_ss << aes_to_string(stream.finalize());

            ciphertext_stream_data = encryption_ss.str();
        }

        BOOST_REQUIRE(!ciphertext_stream_data.empty());

        std::string planetext_stream_data;
        {
            std::stringstream source_ss { ciphertext_stream_data };
            std::stringstream encryption_ss;

            char buff[chunk_size];

            // Read mark
            source_ss.read(buff, ADD_MARK.size());
            buff[ADD_MARK.size()] = 0;
            BOOST_REQUIRE_EQUAL(std::string { buff }, ADD_MARK);

            aes_decryption_stream stream { default_context_with_crypto_api(), key, ADD_MARK };

            stream.start();

            aes_tag_type tag;

            // Decryption cycle
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

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        std::string data_;

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_NO_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))));

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_small_encryption_with_add_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string add_mark { "(a)" };
        const std::string key { "Secret Key" };

        std::string data = create_test_data(data_sz);

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        enc_stream.start(key, add_mark);
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        std::string data_;

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key, add_mark);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_NO_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))));

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_data_encryption_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        const std::string key { "Secret Key" };

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        // Corrupt!
        ciphertext_stream_data[data.size() / 2] = ~ciphertext_stream_data[data.size() / 2];

        std::string data_;

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_tag_encryption_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        const std::string key { "Secret Key" };

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        ciphertext_stream_data.append(enc_stream.start(key));
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        // Corrupt!
        ciphertext_stream_data[data.size() + 8] = ~ciphertext_stream_data[data.size() + 8];

        std::string data_;

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);

        // Failed finalization but data correct
        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_corrupted_add_encryption_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        std::string add_mark { "(a)" };
        const std::string key { "Secret Key" };

        std::string ciphertext_stream_data;
        ciphertext_stream_data.reserve(data.size() + 16);

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        enc_stream.start(key, add_mark);
        ciphertext_stream_data.append(enc_stream.encrypt(data));
        ciphertext_stream_data.append(aes_to_string(enc_stream.finalize()));

        BOOST_REQUIRE(!ciphertext_stream_data.empty());
        BOOST_REQUIRE_EQUAL(ciphertext_stream_data.size(), data.size() + 16);

        // Corrupt!
        add_mark[add_mark.size() / 2] = ~add_mark[add_mark.size() / 2];

        std::string data_;

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key, add_mark);
        data_ = dec_stream.decrypt(ciphertext_stream_data.substr(0, data.size()));
        BOOST_REQUIRE_THROW(dec_stream.finalize(aes_from_string(ciphertext_stream_data.substr(data.size(), 16))), std::logic_error);

        // Failed finalization but data correct
        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(stream_odd_size_check)
    {
        print_current_test_name();

        const size_t odd_sz = 123;

        std::string data = create_test_data(odd_sz);

        BOOST_REQUIRE_EQUAL(data.size(), odd_sz);

        DUMP_STR(to_printable(data));

        const std::string key { "Secret Key" };

        aes_encryption_stream enc_stream(default_context_with_crypto_api());
        auto ecrypted_data = enc_stream.start(key);
        ecrypted_data.append(enc_stream.encrypt(data));
        enc_stream.finalize();

        DUMP_STR(to_printable(ecrypted_data));

        aes_decryption_stream dec_stream(default_context_with_crypto_api());
        dec_stream.start(key);
        auto data2 = dec_stream.decrypt(ecrypted_data);
        dec_stream.finalize();

        BOOST_REQUIRE_EQUAL(data, data2);
    }

    BOOST_AUTO_TEST_CASE(stream_invalid_usage_check)
    {
        print_current_test_name();

        const size_t data_sz = 256;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        aes_encryption_stream enc_stream(default_context_with_crypto_api());

        BOOST_REQUIRE_THROW(enc_stream.encrypt(data), std::logic_error);
        BOOST_REQUIRE_THROW(enc_stream.finalize(), std::logic_error);

        auto ecrypted_data = enc_stream.start(key);
        ecrypted_data.append(enc_stream.encrypt(data));
        enc_stream.finalize();

        aes_decryption_stream dec_stream(default_context_with_crypto_api());

        BOOST_REQUIRE_THROW(dec_stream.decrypt(ecrypted_data), std::logic_error);
        BOOST_REQUIRE_THROW(dec_stream.finalize(), std::logic_error);

        dec_stream.start(key);
        auto data2 = dec_stream.decrypt(ecrypted_data);
        dec_stream.finalize();

        BOOST_REQUIRE_EQUAL(data, data2);
    }

    BOOST_AUTO_TEST_CASE(salted_key_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        const std::string key { "Simple Key" };

        std::vector<std::string> cipher_key_history;
        std::vector<std::string> salt_history;

        const size_t times = 3;

        for (size_t ci = 0; ci < times; ++ci)
        {
            auto key_data = aes_create_salted_key(default_context_with_crypto_api(), key);

            std::string cipher_key = key_data.first;
            // Pass or save separately from key!
            std::string salt = to_base64(aes_to_string(key_data.second));

            DUMP_STR(to_base64(cipher_key));
            DUMP_STR(salt);

            auto cipher_data = aes_encrypt(default_context_with_crypto_api(), data, cipher_key);

            BOOST_REQUIRE(!cipher_data.empty());

            auto data_ = aes_decrypt(default_context_with_crypto_api(), cipher_data, aes_get_salted_key(key, from_base64(salt)));

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

        const size_t data_sz = 256;

        std::string data = create_test_data(data_sz);

        const std::string key { "Secret Key" };

        auto store_chunk = [](std::stringstream& ss, const std::string& chunk) {
            size_t sz = chunk.size();
            // There is more compact way to store digital value
            // but this simple way used for test
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
        aes_encryption_stream enc(default_context_with_crypto_api(), key, "x");

        std::string input_chunk = data + "--S1--";

        store_chunk(encryption_ss, enc.start());
        store_chunk(encryption_ss, enc.encrypt(input_chunk));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(input_chunk);

        input_chunk = data + data + "--S2--";

        store_chunk(encryption_ss, enc.start());
        store_chunk(encryption_ss, enc.encrypt(input_chunk));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(input_chunk);

        const std::string new_key { "New Key Only For One Next Session" };

        input_chunk = data + data + "--S3--";

        store_chunk(encryption_ss, enc.start(new_key));
        store_chunk(encryption_ss, enc.encrypt(input_chunk));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(input_chunk);

        input_chunk = data + "--S4--";

        // Restore previous key but use new ADD
        store_chunk(encryption_ss, enc.start({}, "x2"));
        store_chunk(encryption_ss, enc.encrypt(input_chunk));
        store_chunk(encryption_ss, aes_to_string(enc.finalize()));

        payload.append(input_chunk);

        DUMP_STR(to_printable(payload));
        DUMP_STR(to_printable(encryption_ss.str()));

        std::string payload_;
        aes_decryption_stream dec(default_context_with_crypto_api(), key, "x");

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

    BOOST_AUTO_TEST_CASE(small_file_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string file_content = ""
                                         "I must not fear."
                                         "\n"
                                         "Fear is the mind-killer."
                                         "\n"
                                         "Fear is the little-death that brings total obliteration."
                                         "\n"
                                         "I will face my fear."
                                         "\n"
                                         "I will permit it to pass over me and through me."
                                         "\n"
                                         "And when it has gone past, I will turn the inner eye to see its path."
                                         "\n"
                                         "Where the fear has gone there will be nothing. Only I will remain.";
        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(file_content.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(file_content, file_content.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        tag = from_hex(stored_tag);

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag);

        BOOST_REQUIRE_EQUAL(file_content, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_without_marker_header_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };

        auto& ctx = default_context_with_crypto_api();

        std::string file_content = ""
                                   "I must not fear."
                                   "\n"
                                   "Fear is the mind-killer."
                                   "\n"
                                   "Fear is the little-death that brings total obliteration."
                                   "\n"
                                   "I will face my fear."
                                   "\n"
                                   "I will permit it to pass over me and through me."
                                   "\n"
                                   "And when it has gone past, I will turn the inner eye to see its path."
                                   "\n"
                                   "Where the fear has gone there will be nothing. Only I will remain.";

        BOOST_REQUIRE_LT(file_content.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(file_content, file_content.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_decrypt_file(ctx, temp.generic_string(), key, "", tag);

        BOOST_REQUIRE_EQUAL(file_content, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_wrong_key_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string file_content = ""
                                         "I must not fear."
                                         "\n"
                                         "Fear is the mind-killer."
                                         "\n"
                                         "Fear is the little-death that brings total obliteration."
                                         "\n"
                                         "I will face my fear."
                                         "\n"
                                         "I will permit it to pass over me and through me."
                                         "\n"
                                         "And when it has gone past, I will turn the inner eye to see its path."
                                         "\n"
                                         "Where the fear has gone there will be nothing. Only I will remain.";
        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(file_content.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(file_content, file_content.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        std::string stored_tag = to_hex(tag);

        DUMP_STR(to_printable(get_file_content(temp)));
        DUMP_STR(to_printable(stored_tag));

        tag = from_hex(stored_tag);

        BOOST_REQUIRE_THROW(aes_decrypt_file(ctx, temp.generic_string(), wrong_key, encrypted_file_marker, tag), std::logic_error);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(small_file_encryption_wrong_key_without_tag_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        const std::string file_content = ""
                                         "I must not fear."
                                         "\n"
                                         "Fear is the mind-killer."
                                         "\n"
                                         "Fear is the little-death that brings total obliteration."
                                         "\n"
                                         "I will face my fear."
                                         "\n"
                                         "I will permit it to pass over me and through me."
                                         "\n"
                                         "And when it has gone past, I will turn the inner eye to see its path."
                                         "\n"
                                         "Where the fear has gone there will be nothing. Only I will remain.";
        const std::string encrypted_file_marker = "DUNE-SECRET";

        BOOST_REQUIRE_LT(file_content.size(), ctx().file_buffer_size());

        boost::filesystem::path temp = create_readable_data_file(file_content, file_content.size(), boost::unit_test::framework::current_test_case().p_name);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        DUMP_STR(to_printable(get_file_content(temp)));

        aes_decrypt_file(ctx, temp.generic_string(), wrong_key, encrypted_file_marker);

        DUMP_STR(to_printable(get_file_content(temp)));

        BOOST_REQUIRE_NE(file_content, get_file_content(temp));

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_check)
    {
        print_current_test_name();

        const std::string key { "Secret Key" };
        const std::string encrypted_file_marker = "XXX";

        auto& ctx = default_context_with_crypto_api();

        boost::filesystem::path temp = create_readable_data_file("LoNg TeSt"
                                                                 "\n",
                                                                 ctx().file_buffer_size() * 10, boost::unit_test::framework::current_test_case().p_name);

        auto initial_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(initial_sha256);

        auto tag = aes_encrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker);

        aes_decrypt_file(ctx, temp.generic_string(), key, encrypted_file_marker, tag);

        auto last_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        DUMP_STR(last_sha256);

        BOOST_REQUIRE_EQUAL(initial_sha256, last_sha256);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(file_encryption_without_corruption_by_wrong_psw_check)
    {
        print_current_test_name();

        const std::string secret_key { "Secret Key" };
        const std::string wrong_key { "Wrong Key" };

        auto& ctx = default_context_with_crypto_api();

        boost::filesystem::path temp = create_readable_data_file("LoNg TeSt"
                                                                 "\n",
                                                                 ctx().file_buffer_size() * 10, boost::unit_test::framework::current_test_case().p_name);

        auto initial_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        auto partial_key_hash = create_sha256(secret_key, 8);

        DUMP_STR(to_hex(partial_key_hash));

        std::string encrypted_file_marker = partial_key_hash;

        aes_encrypt_file(ctx, temp.generic_string(), secret_key, encrypted_file_marker);

        std::string file_header;
        {
            std::vector<char> header;
            header.resize(encrypted_file_marker.size());

            std::ifstream f(temp.generic_string(), std::ifstream::binary | std::ifstream::out);
            f.read(header.data(), encrypted_file_marker.size());
            auto bytes_read = f.gcount();

            BOOST_REQUIRE_EQUAL(bytes_read, encrypted_file_marker.size());

            f.close();

            file_header.assign(header.data(), header.size());
        }
        BOOST_REQUIRE_EQUAL(file_header, encrypted_file_marker);

        // Check header before decryption attempt!
        auto wrong_partial_key_hash = create_sha256(wrong_key, 8);

        DUMP_STR(to_hex(wrong_partial_key_hash));

        BOOST_REQUIRE_NE(file_header, wrong_partial_key_hash);
        BOOST_REQUIRE_EQUAL(file_header, partial_key_hash);

        aes_decrypt_file(ctx, temp.generic_string(), secret_key, encrypted_file_marker);

        auto last_sha256 = to_hex(create_sha256_from_file(ctx, temp.generic_string()));

        BOOST_REQUIRE_EQUAL(initial_sha256, last_sha256);

        boost::filesystem::remove(temp);
    }

    BOOST_AUTO_TEST_CASE(flip_flap_with_marker_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        DUMP_STR(to_printable(data));

        const std::string key { "Temp Key" };
        const std::string marker { "%%" };

        auto flip_data = aes_ecnrypt_flip(default_context_with_crypto_api(), data, key, marker, true); // flip

        const auto& session_data = flip_data.second;

        DUMP_STR(to_printable(session_data)); // flip data

        const auto& cipher_data = flip_data.first;

        DUMP_STR(to_printable(cipher_data)); // flap data

        auto data_ = aes_decrypt_flip(default_context_with_crypto_api(), cipher_data, session_data, key, marker); // flap

        BOOST_REQUIRE_EQUAL(data, data_);
    }

    BOOST_AUTO_TEST_CASE(flip_flap_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        DUMP_STR(to_printable(data));

        const std::string base_key { "Temp Key" };

        for (size_t ci = 0; ci < 5; ++ci)
        {
            std::string key = base_key + std::to_string(ci + 1);

            auto flip_data = aes_ecnrypt_flip(default_context_with_crypto_api(), data, key, {}, true); // flip

            const auto& session_data = flip_data.second;

            DUMP_STR(to_printable(session_data)); // flip data

            const auto& cipher_data = flip_data.first;

            DUMP_STR(to_printable(cipher_data)); // flap data

            auto data_ = aes_decrypt_flip(default_context_with_crypto_api(), cipher_data, session_data, key); // flap

            BOOST_REQUIRE_EQUAL(data, data_);
        }
    }

    BOOST_AUTO_TEST_CASE(simplest_flip_flap_check)
    {
        print_current_test_name();

        const size_t data_sz = 1024;

        std::string data = create_test_data(data_sz);

        DUMP_STR(to_printable(data));

        const std::string key { "Temp Key3" };

        for (size_t ci = 0; ci < 5; ++ci)
        {
            auto flip_data = aes_ecnrypt_flip(default_context_with_crypto_api(), data, key); // flip

            const auto& session_data = flip_data.second;

            DUMP_STR(to_printable(session_data)); // flip data

            const auto& cipher_data = flip_data.first;

            DUMP_STR(to_printable(cipher_data)); // flap data

            auto data_ = aes_decrypt_flip(default_context_with_crypto_api(), cipher_data, session_data, key); // flap

            BOOST_REQUIRE_EQUAL(data, data_);
        }
    }

    BOOST_AUTO_TEST_SUITE_END()
} // namespace tests
} // namespace ssl_helpers
