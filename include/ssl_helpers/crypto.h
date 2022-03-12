#pragma once

#include <cstddef>

#include <string>
#include <functional>
#include <memory>

#include <ssl_helpers/context.h>

#include "crypto_types.h"


namespace ssl_helpers {

// Create tagged ecrypted data stream that includes tag data of encrypted plane data
// and optional marker that is ADD (Additional Authenticated Data).
// Implementation guarantee authenticity of marker and data through the tag (TAG).
// Data stream (from top down to bottom):
//
//     |ADD (can be readable data)|
//     |Encrypted plane data (binary)| -> transfer by chunks
//     |TAG (binary with 16 size)|
//

class aes_encryption_stream
{
public:
    aes_encryption_stream(const context&,
                          const std::string& default_key = {},
                          const std::string& default_add = {});
    ~aes_encryption_stream();

    // Start encryption session.
    std::string start(const std::string& key = {},
                      const std::string& add = {});

    // Encrypt chunk of plane data
    std::string encrypt(const std::string& plain_chunk);

    // Finalize encryption session and create tag.
    aes_tag_type finalize();

private:
    std::unique_ptr<impl::__aes_encryption_stream> _impl;
};


// Decrypt tagged ecrypted data stream to plane data.

class aes_decryption_stream
{
public:
    aes_decryption_stream(const context&,
                          const std::string& default_key = {},
                          const std::string& default_add = {});
    ~aes_decryption_stream();

    // Start decryption session.
    void start(const std::string& key = {},
               const std::string& add = {});

    // Decrypt chunk of cipher data.
    std::string decrypt(const std::string& cipher_chunk);

    // Finalize decryption session and check stream tag.
    void finalize(const aes_tag_type& tag);

    // Finalize decryption without check (for custom implementation)
    void finalize();

private:
    std::unique_ptr<impl::__aes_decryption_stream> _impl;
};


// Improve crypto resistance by using PBKDF2.

// Create random salt apply PBKDF2.
salted_key_type aes_create_salted_key(const context&, const std::string& key);

// Apply PBKDF2 for input salt.
std::string aes_get_salted_key(const std::string& key, const std::string& salt);
std::string aes_get_salted_key(const std::string& key, const aes_salt_type& salt);


// Encrypt data at once.

std::string aes_encrypt(const context&, const std::string& plain_data, const std::string& key);

// Provide authenticity of data with custom function.
std::string aes_encrypt(const context&,
                        const std::string& plain_data, const std::string& key,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag,
                        std::string& created_check_tag);

// Decrypt data at once.

std::string aes_decrypt(const context&,
                        const std::string& cipher_data, const std::string& key);

// Provide authenticity of data with custom function.
std::string aes_decrypt(const context&,
                        const std::string& cipher_data, const std::string& key,
                        const std::string& check_tag,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag);


// Encrypt file.
// WARNING:
//      This function encode file inplace with only std and boost::filesystem
//      crossplatform functions.
//      Therefore it is not atomic and should create corrupted result if some
//      other process or thread modify this file at the same time.
//
//      There are no ways to do it atomic without platform specific logic
//      and it will be pretty difficult for some platform and solution
//      will be depended on bussiness logic (for your application targets)
//
// RECOMMENDATION:
//      It is more safe to use this function if you copy file to temporary
//      safty path before (for instance mapped in memory) and replace initial file after.
//      It is possible to do smart atomic replace function for certain platform
//      if you expect guarantees that initial file plane data chunks will be
//      deleted from disk after encryption or not just marked by file system
//      as deleted and can be restored.

// Use 'marker' argument like file type sign.

std::string aes_encrypt_file(const context& ctx,
                             const std::string& path, const std::string& key,
                             const std::string& marker = {});

// Decrypt file.

void aes_decrypt_file(const context& ctx,
                      const std::string& path, const std::string& key,
                      const std::string& marker = {},
                      const std::string& tag = {});


// 'Flip/Flap' technique to transfer both encrypted data and key through unencrypted network.
// Idea is suppose data are transferred by three chunks separated in time
// and useless individually.
// This chunks are not classical cipher data, initialization vector
// and cipher key to prevent easy reveal. By default session key has unpredictable
// size (add_garbage) otherwise this chunk has fixed size.
// One can improve security if will transfer chunks via different data channels.
// Chunks:
//     1. Instant key
//     2. Cipher data
//     3. Session key

// Encrypt data at once (Flip).

flip_session_type aes_ecnrypt_flip(const context&,
                                   const std::string& plain_data,
                                   const std::string& instant_key,
                                   const std::string& marker = {},
                                   bool add_garbage = true);

// Decrypt data at once (Flap).

std::string aes_decrypt_flip(const context&,
                             const flip_session_type& session_data,
                             const std::string& instant_key,
                             const std::string& marker = {});
std::string aes_decrypt_flip(const context&,
                             const std::string& cipher_data,
                             const std::string& session_key,
                             const std::string& instant_key,
                             const std::string& marker = {});

} // namespace ssl_helpers
