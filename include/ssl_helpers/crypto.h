#pragma once

#include <string>
#include <functional>
#include <memory>

namespace ssl_helpers {

namespace impl {
    class aes_encryption_stream_impl;
    class aes_decryption_stream_impl;
} // namespace impl

//Create tagged data stream that includes tag data of encrypted stream
//and optionally ADD (Additional Authenticated Data)
//Implementation guarantee authenticity of ADD and Data through the tag.
//  Stream:
//
// -> |ADD (can be readable)|encrypted data (bynary)|TAG (bynary 16 sz)|
//

class aes_encryption_stream
{
public:
    //these KEY and ADD will be stored for each encryption session if no one set in this->start
    aes_encryption_stream(const std::string& key = {}, const std::string& additional_authenticated_data = {});
    ~aes_encryption_stream();

    //start encryption session. Key is required here or in constructor
    std::string start(const std::string& key = {}, const std::string& add = {});
    std::string encrypt(const std::string& plain_chunk);
    //finalize encryption session and create tag
    std::string finalize();

    //helpers to navigate in stream
    size_t last_add_size() const;
    size_t last_ecryption_size() const;
    size_t tag_size() const;

private:
    std::unique_ptr<impl::aes_encryption_stream_impl> _impl;
};

class aes_decryption_stream
{
public:
    //these KEY and ADD will be stored for each decryption session if no one set in this->start
    aes_decryption_stream(const std::string& key = {}, const std::string& additional_authenticated_data = {});
    ~aes_decryption_stream();

    //start decryption session. Key is required here or in constructor
    void start(const std::string& key = {}, const std::string& add = {});
    std::string decrypt(const std::string& cipher_chunk);
    //finalize decryption session and check input tag
    void finalize(const std::string& tag);

private:
    std::unique_ptr<impl::aes_decryption_stream_impl> _impl;
};

//Improve crypto resistance by using PBKDF2
//

using salted_key_type = std::pair<std::string /*encryption key*/, std::string /*random salt*/>;
salted_key_type aes_create_salted_key(const std::string& user_key);
std::string aes_get_salted_key(const std::string& user_key, const std::string& salt);

//Encrypt data at once. It can be provide authenticity of data with custom ctreate_check_tag function
//

std::string aes_encrypt(const std::string& key, const std::string& plain_data);
std::string aes_encrypt(const std::string& key, const std::string& plain_data,
                        std::function<std::string(const std::string& key, const std::string& cipherdata)> ctreate_check_tag,
                        std::string& check_tag);

std::string aes_decrypt(const std::string& key, const std::string& cipherdata);
std::string aes_decrypt(const std::string& key, const std::string& cipherdata, const std::string& check_tag,
                        std::function<std::string(const std::string& key, const std::string& cipherdata)> ctreate_check_tag);

//Encrypt file with key and providing check tag.
//Use ADD like file type marker.
//Warning:
//  on POSIX systems you can happily read and write a file already opened by another process.
//  Therefore lock file writing before encrypt this to prevent corruption!
//

// return check tag
std::string aes_encrypt_file(const std::string& path, const std::string& key, const std::string& add = {});
void aes_decrypt_file(const std::string& path, const std::string& key, const std::string& tag, const std::string& add = {});

} // namespace ssl_helpers
