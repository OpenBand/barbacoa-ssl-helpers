#include "ssl_helpers_defines.h"

#include "aes256.h"

#include <cstring>

namespace ssl_helpers {
namespace impl {

    template <class aes_array_type>
    aes_array_type create_from_string_impl(const char* pstr, size_t len)
    {
        aes_array_type result;

        SSL_HELPERS_ASSERT(len >= std::tuple_size<aes_array_type>::value, "Insufficient size of initializing data");

        std::memcpy(result.data(), pstr, result.size());

        return result;
    }

    template <class aes_array_type>
    std::string to_string_impl(const aes_array_type& data)
    {
        return { data.data(), data.size() };
    }

    template <>
    aes_512bit_type create_from_string<aes_512bit_type>(const char* pstr, size_t len)
    {
        return create_from_string_impl<aes_512bit_type>(pstr, len);
    }

    template <>
    aes_256bit_type create_from_string<aes_256bit_type>(const char* pstr, size_t len)
    {
        return create_from_string_impl<aes_256bit_type>(pstr, len);
    }

    template <>
    std::string to_string<aes_512bit_type>(const aes_512bit_type& data)
    {
        return to_string_impl<aes_512bit_type>(data);
    }

    template <>
    std::string to_string<aes_256bit_type>(const aes_256bit_type& data)
    {
        return to_string_impl<aes_256bit_type>(data);
    }

    aes_stream_encryptor::aes_stream_encryptor()
    {
        init_openssl();

        _ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(_ctx, ERR_error_string(ERR_get_error(), nullptr));
    }

    aes_stream_encryptor::~aes_stream_encryptor()
    {
        EVP_CIPHER_CTX_free(_ctx);
    }

    void aes_stream_encryptor::init(const gcm_key_type& key, const gcm_iv_type& init_value)
    {
        auto cypher_init_result = (1 == EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result_2 = (1 == EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL));
        SSL_HELPERS_ASSERT(cypher_init_result_2, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result_3 = (1 == EVP_EncryptInit_ex(_ctx, NULL, NULL, (unsigned char*)key.data(), (unsigned char*)init_value.data()));
        SSL_HELPERS_ASSERT(cypher_init_result_3, ERR_error_string(ERR_get_error(), nullptr));
    }

    void aes_stream_encryptor::set_add(const char* aad, size_t len)
    {
        int len_ = 0;

        auto cypher_init_result = (1 == EVP_EncryptUpdate(_ctx, NULL, &len_, (unsigned char*)aad, len));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));
    }

    size_t aes_stream_encryptor::process(const char* plain_chunk, size_t len, char* cipher_chunk)
    {
        int cipher_data_len = 0;

        SSL_HELPERS_ASSERT(_ctx);

        auto cypher_encode_result = (1 == EVP_EncryptUpdate(_ctx, (unsigned char*)cipher_chunk, &cipher_data_len, (const unsigned char*)plain_chunk, len));
        SSL_HELPERS_ASSERT(cypher_encode_result, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(cipher_data_len > 0 && cipher_data_len == (int)len, "Chunk size has deviated");
        return static_cast<size_t>(cipher_data_len);
    }

    void aes_stream_encryptor::finalize(gcm_tag_type& tag)
    {
        int len_ = 0;

        auto cypher_fin_result_1 = (1 == EVP_EncryptFinal_ex(_ctx, NULL, &len_));
        SSL_HELPERS_ASSERT(cypher_fin_result_1, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(!len_);

        auto cypher_fin_result_2 = (1 == EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()));
        SSL_HELPERS_ASSERT(cypher_fin_result_2, ERR_error_string(ERR_get_error(), nullptr));
    }

    aes_stream_decryptor::aes_stream_decryptor()
    {
        init_openssl();

        _ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(_ctx, ERR_error_string(ERR_get_error(), nullptr));
    }

    aes_stream_decryptor::~aes_stream_decryptor()
    {
        EVP_CIPHER_CTX_free(_ctx);
    }

    void aes_stream_decryptor::init(const gcm_key_type& key, const gcm_iv_type& init_value)
    {
        auto cypher_init_result = (1 == EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result_2 = (1 == EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL));
        SSL_HELPERS_ASSERT(cypher_init_result_2, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result_3 = (1 == EVP_DecryptInit_ex(_ctx, NULL, NULL, (unsigned char*)key.data(), (unsigned char*)init_value.data()));
        SSL_HELPERS_ASSERT(cypher_init_result_3, ERR_error_string(ERR_get_error(), nullptr));
    }

    void aes_stream_decryptor::set_add(const char* aad, size_t len)
    {
        int len_ = 0;

        auto cypher_init_result = (1 == EVP_DecryptUpdate(_ctx, NULL, &len_, (unsigned char*)aad, len));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));
    }

    size_t aes_stream_decryptor::process(const char* cipher_chunk, size_t len, char* plain_chunk)
    {
        int plain_data_len = 0;

        SSL_HELPERS_ASSERT(_ctx);

        auto cypher_decode_result = (1 == EVP_DecryptUpdate(_ctx, (unsigned char*)plain_chunk, &plain_data_len, (const unsigned char*)cipher_chunk, len));
        SSL_HELPERS_ASSERT(cypher_decode_result, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(plain_data_len > 0 && plain_data_len == (int)len, "Chunk size has deviated");
        return static_cast<size_t>(plain_data_len);
    }

    void aes_stream_decryptor::finalize(gcm_tag_type& tag)
    {
        int len_ = 0;

        auto cypher_fin_result_1 = (1 == EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()));
        SSL_HELPERS_ASSERT(cypher_fin_result_1, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_fin_result_2 = (1 == EVP_DecryptFinal_ex(_ctx, NULL, &len_));
        SSL_HELPERS_ASSERT(cypher_fin_result_2, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(!len_);
    }

    aes_block::aes_block()
    {
        init_openssl();
    }

    unsigned aes_block::encrypt(unsigned char* plain_data, int plain_data_len, unsigned char* key,
                                unsigned char* iv, unsigned char* cipher_data)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(ctx, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result = (1 == EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        int len = 0;
        unsigned cipher_data_len = 0;

        auto cypher_encode_result = (1 == EVP_EncryptUpdate(ctx, cipher_data, &len, plain_data, plain_data_len));
        SSL_HELPERS_ASSERT(cypher_encode_result, ERR_error_string(ERR_get_error(), nullptr));
        cipher_data_len = len;

        auto cypher_final_result = (1 == EVP_EncryptFinal_ex(ctx, cipher_data + len, &len));
        SSL_HELPERS_ASSERT(cypher_final_result, ERR_error_string(ERR_get_error(), nullptr));
        cipher_data_len += len;

        return cipher_data_len;
    }

    unsigned aes_block::decrypt(unsigned char* cipher_data, int cipher_data_len, unsigned char* key,
                                unsigned char* iv, unsigned char* plain_data)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(ctx, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result = (1 == EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        int len = 0;
        unsigned plain_data_len = 0;

        auto cypher_decode_result = (1 == EVP_DecryptUpdate(ctx, plain_data, &len, cipher_data, cipher_data_len));
        SSL_HELPERS_ASSERT(cypher_decode_result, ERR_error_string(ERR_get_error(), nullptr));
        plain_data_len = len;

        auto cypher_final_result = (1 == EVP_DecryptFinal_ex(ctx, plain_data + len, &len));
        SSL_HELPERS_ASSERT(cypher_final_result, ERR_error_string(ERR_get_error(), nullptr));
        plain_data_len += len;

        return plain_data_len;
    }

    std::vector<char> aes_block::encrypt(const sha512& key, const char* plain_data, size_t len)
    {
        std::vector<char> cipher_data(len + 16);
        auto cipher_len = encrypt((unsigned char*)plain_data, (int)len,
                                  (unsigned char*)key.data(), ((unsigned char*)key.data()) + 32,
                                  (unsigned char*)cipher_data.data());
        SSL_HELPERS_ASSERT(cipher_len <= cipher_data.size());
        cipher_data.resize(cipher_len);
        return cipher_data;
    }
    std::vector<char> aes_block::decrypt(const sha512& key, const char* cipher_data, size_t len)
    {
        std::vector<char> plain_data(len);
        auto plain_len = decrypt((unsigned char*)cipher_data, (int)len,
                                 (unsigned char*)key.data(), ((unsigned char*)key.data()) + 32,
                                 (unsigned char*)plain_data.data());
        plain_data.resize(plain_len);
        return plain_data;
    }


} // namespace impl
} // namespace ssl_helpers
