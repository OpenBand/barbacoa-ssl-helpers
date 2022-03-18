#pragma once

#include <string>
#include <vector>
#include <array>

#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#include "sha256.h"
#include "sha512.h"


namespace ssl_helpers {
namespace impl {

    using aes_512bit_type = std::array<char, 32>;
    using aes_256bit_type = std::array<char, 16>;

    using gcm_key_type = aes_512bit_type;
    using gcm_iv_type = aes_256bit_type;
    using gcm_tag_type = aes_256bit_type;

    template <class aes_array_type>
    aes_array_type create_from_string(const char*, size_t);

    template <class aes_array_type>
    std::string to_string(const aes_array_type&);


    // AES256 + 128iv, AEAD-GSM mode
    //
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    //
    class aes_stream_encryptor
    {
    public:
        aes_stream_encryptor() = default;
        ~aes_stream_encryptor();

        void init(const gcm_key_type& key, const gcm_iv_type& init_value);

        // This can be called zero or more times as required
        // to set public authorization information.
        void set_add(const char* additional_authenticated_data, size_t len);

        // Encrypt. It can be called multiple times to process
        // all plane data.
        size_t process(const char* plain_chunk, size_t len, char* cipher_chunk);

        // Finish encryption and get check tag.
        void finalize(gcm_tag_type&);

    private:
        EVP_CIPHER_CTX* _ctx = NULL;
    };


    // AES256 + 128iv, AEAD-GSM mode
    //
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    //
    class aes_stream_decryptor
    {
    public:
        aes_stream_decryptor() = default;
        ~aes_stream_decryptor();

        void init(const gcm_key_type& key, const gcm_iv_type& init_value);

        // This can be called zero or more times as required
        // to set public authorization information.
        void set_add(const char* additional_authenticated_data, size_t len);

        // Decrypt. It can be called multiple times to process
        // all encrypted data.
        size_t process(const char* cipher_chunk, size_t len, char* plain_chunk);

        // Finish decryption and check by tag.
        void finalize(gcm_tag_type&);

    private:
        EVP_CIPHER_CTX* _ctx = NULL;
    };


    // AES256 + fixed 128iv, CBC mode
    //
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    //
    //  Warning:
    //      It is recommended to use custom data check method
    //      otherwise data can been tampered.
    class aes_block
    {
    public:
        aes_block() = default;

        // Key and init value (initialization vector) are set in common complicated 512 passphrase
        std::vector<char> encrypt(const sha512& key, const char* plain_data, size_t len);
        std::vector<char> decrypt(const sha512& key, const char* cipher_data, size_t len);

    private:
        unsigned encrypt(unsigned char* plain_data, int len, unsigned char* key,
                         unsigned char* iv, unsigned char* cipher_data);
        unsigned decrypt(unsigned char* cipher_data, int len, unsigned char* key,
                         unsigned char* iv, unsigned char* plain_data);
    };

} // namespace impl
} // namespace ssl_helpers
