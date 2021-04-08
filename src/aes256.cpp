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

        std::memcpy(result.data(), pstr, std::tuple_size<aes_array_type>::value);

        return result;
    }

    template <class aes_array_type>
    std::string to_string_impl(const aes_array_type& data)
    {
        return { data.data(), std::tuple_size<aes_array_type>::value };
    }

    template <>
    gcm_iv_type create_from_string<gcm_iv_type>(const char* pstr, size_t len)
    {
        return create_from_string_impl<gcm_iv_type>(pstr, len);
    }

    template <>
    gcm_key_type create_from_string<gcm_key_type>(const char* pstr, size_t len)
    {
        return create_from_string_impl<gcm_key_type>(pstr, len);
    }

    template <>
    std::string to_string<gcm_iv_type>(const gcm_iv_type& data)
    {
        return to_string_impl<gcm_iv_type>(data);
    }

    template <>
    std::string to_string<gcm_key_type>(const gcm_key_type& data)
    {
        return to_string_impl<gcm_key_type>(data);
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

    size_t aes_stream_encryptor::process(const char* plain_text_chunk, size_t len, char* cipher_text_chunk)
    {
        int ciphertext_len = 0;

        SSL_HELPERS_ASSERT(_ctx);

        auto cypher_encode_result = (1 == EVP_EncryptUpdate(_ctx, (unsigned char*)cipher_text_chunk, &ciphertext_len, (const unsigned char*)plain_text_chunk, len));
        SSL_HELPERS_ASSERT(cypher_encode_result, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(ciphertext_len > 0 && ciphertext_len == (int)len, "Chunk size has deviated");
        return static_cast<size_t>(ciphertext_len);
    }

    void aes_stream_encryptor::finalize(gcm_tag_type& tag)
    {
        int len_ = 0;

        //        auto cypher_fin_result_1 = (1 == EVP_EncryptFinal_ex(_ctx, (unsigned char*)(cipher_text + len), &len_));
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

    size_t aes_stream_decryptor::process(const char* cipher_text_chunk, size_t len, char* plain_text_chunk)
    {
        int plaintext_len = 0;

        SSL_HELPERS_ASSERT(_ctx);

        auto cypher_encode_result = (1 == EVP_DecryptUpdate(_ctx, (unsigned char*)plain_text_chunk, &plaintext_len, (const unsigned char*)cipher_text_chunk, len));
        SSL_HELPERS_ASSERT(cypher_encode_result, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(plaintext_len > 0 && plaintext_len == (int)len, "Chunk size has deviated");
        return static_cast<size_t>(plaintext_len);
    }

    void aes_stream_decryptor::finalize(gcm_tag_type& tag)
    {
        int len_ = 0;

        auto cypher_fin_result_1 = (1 == EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()));
        SSL_HELPERS_ASSERT(cypher_fin_result_1, ERR_error_string(ERR_get_error(), nullptr));

        //        auto cypher_fin_result_2 = (1 == EVP_DecryptFinal_ex(_ctx, (unsigned char*)(plain_text_chunk + len), &len_));
        auto cypher_fin_result_2 = (1 == EVP_DecryptFinal_ex(_ctx, NULL, &len_));
        SSL_HELPERS_ASSERT(cypher_fin_result_2, ERR_error_string(ERR_get_error(), nullptr));

        SSL_HELPERS_ASSERT(!len_);
    }

    aes_block::aes_block()
    {
        init_openssl();
    }

    unsigned aes_block::encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
                                unsigned char* iv, unsigned char* ciphertext)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(ctx, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result = (1 == EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        int len = 0;
        unsigned ciphertext_len = 0;

        auto cypher_encode_result = (1 == EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
        SSL_HELPERS_ASSERT(cypher_encode_result, ERR_error_string(ERR_get_error(), nullptr));
        ciphertext_len = len;

        auto cypher_final_result = (1 == EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));
        SSL_HELPERS_ASSERT(cypher_final_result, ERR_error_string(ERR_get_error(), nullptr));
        ciphertext_len += len;

        return ciphertext_len;
    }

    unsigned aes_block::decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
                                unsigned char* iv, unsigned char* plaintext)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        SSL_HELPERS_ASSERT(ctx, ERR_error_string(ERR_get_error(), nullptr));

        auto cypher_init_result = (1 == EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
        SSL_HELPERS_ASSERT(cypher_init_result, ERR_error_string(ERR_get_error(), nullptr));

        int len = 0;
        unsigned plaintext_len = 0;

        auto cypher_decode_result = (1 == EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len));
        SSL_HELPERS_ASSERT(cypher_decode_result, ERR_error_string(ERR_get_error(), nullptr));
        plaintext_len = len;

        auto cypher_final_result = (1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len));
        SSL_HELPERS_ASSERT(cypher_final_result, ERR_error_string(ERR_get_error(), nullptr));
        plaintext_len += len;

        return plaintext_len;
    }

    std::vector<char> aes_block::encrypt(const sha512& key, const char* plain_text, size_t len)
    {
        std::vector<char> cipher_text(len + 16);
        auto cipher_len = encrypt((unsigned char*)plain_text, (int)len,
                                  (unsigned char*)key.data(), ((unsigned char*)key.data()) + 32,
                                  (unsigned char*)cipher_text.data());
        SSL_HELPERS_ASSERT(cipher_len <= cipher_text.size());
        cipher_text.resize(cipher_len);
        return cipher_text;
    }
    std::vector<char> aes_block::decrypt(const sha512& key, const char* cipher_text, size_t len)
    {
        std::vector<char> plain_text(len);
        auto plain_len = decrypt((unsigned char*)cipher_text, (int)len,
                                 (unsigned char*)key.data(), ((unsigned char*)key.data()) + 32,
                                 (unsigned char*)plain_text.data());
        plain_text.resize(plain_len);
        return plain_text;
    }


} // namespace impl
} // namespace ssl_helpers
