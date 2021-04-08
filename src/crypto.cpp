#include <ssl_helpers/crypto.h>
#include <ssl_helpers/hash.h>

#include <openssl/rand.h>

#include "crypto_stream_impl.h"
#include "sha256.h"
#include "inplace.h"

namespace ssl_helpers {

aes_encryption_stream::aes_encryption_stream(const std::string& key, const std::string& add)
{
    try
    {
        _impl = std::make_unique<impl::aes_encryption_stream_impl>(key, add);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}
aes_encryption_stream::~aes_encryption_stream()
{
}
std::string aes_encryption_stream::start(const std::string& key, const std::string& add)
{
    try
    {
        return _impl->start(key, add);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}
std::string aes_encryption_stream::encrypt(const std::string& plain_chunk)
{
    try
    {
        return _impl->encrypt(plain_chunk);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}
std::string aes_encryption_stream::finalize()
{
    try
    {
        return _impl->finalize();
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}

size_t aes_encryption_stream::last_add_size() const
{
    return _impl->last_add_size();
}
size_t aes_encryption_stream::last_ecryption_size() const
{
    return _impl->last_ecryption_size();
}
size_t aes_encryption_stream::tag_size() const
{
    return _impl->tag_size();
}

aes_decryption_stream::aes_decryption_stream(const std::string& key, const std::string& add)
{
    try
    {
        _impl = std::make_unique<impl::aes_decryption_stream_impl>(key, add);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}
aes_decryption_stream::~aes_decryption_stream()
{
}
void aes_decryption_stream::start(const std::string& key, const std::string& add)
{
    try
    {
        _impl->start(key, add);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}
std::string aes_decryption_stream::decrypt(const std::string& cipher_chunk)
{
    try
    {
        return _impl->decrypt(cipher_chunk);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}
void aes_decryption_stream::finalize(const std::string& tag)
{
    try
    {
        _impl->finalize(tag);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}

salted_key_type aes_create_salted_key(const std::string& user_key)
{
    try
    {
        SSL_HELPERS_ASSERT(!user_key.empty(), "Key required");

        impl::init_openssl();

        using salt_type = std::array<char, 16>;
        salt_type salt;
        SSL_HELPERS_ASSERT(1 == RAND_bytes((unsigned char*)salt.data(), std::tuple_size<salt_type>::value), "Can't get random data for salt");

        std::string salt_str { salt.data(), std::tuple_size<salt_type>::value };
        return { create_pbkdf2_512(user_key, salt_str), salt_str };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_get_salted_key(const std::string& user_key, const std::string& salt)
{
    try
    {
        SSL_HELPERS_ASSERT(!user_key.empty(), "Key required");
        SSL_HELPERS_ASSERT(!salt.empty(), "Salt required");

        return create_pbkdf2_512(user_key, salt);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_encrypt(const std::string& key, const std::string& plain_data)
{
    try
    {
        impl::aes_block cipher;
        std::vector<char> result = cipher.encrypt(impl::sha512::hash(key), plain_data.data(), plain_data.size());
        return { result.data(), result.size() };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_encrypt(const std::string& key, const std::string& plain_data,
                        std::function<std::string(const std::string& key, const std::string& cipherdata)> ctreate_check_tag,
                        std::string& check_tag)
{
    try
    {
        impl::aes_block cipher;
        std::string result_str;
        {
            std::vector<char> result = cipher.encrypt(impl::sha512::hash(key), plain_data.data(), plain_data.size());
            result_str = { result.data(), result.size() };
        }
        check_tag = ctreate_check_tag(key, result_str);
        return result_str;
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_decrypt(const std::string& key, const std::string& cipherdata)
{
    try
    {
        impl::aes_block cipher;
        std::vector<char> result = cipher.decrypt(impl::sha512::hash(key), cipherdata.data(), cipherdata.size());
        return { result.data(), result.size() };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_decrypt(const std::string& key, const std::string& cipherdata, const std::string& check_tag,
                        std::function<std::string(const std::string& key, const std::string& cipherdata)> ctreate_check_tag)
{
    try
    {
        impl::aes_block cipher;
        auto input_check_tag = ctreate_check_tag(key, cipherdata);
        if (check_tag != input_check_tag)
            return {};

        std::vector<char> result = cipher.decrypt(impl::sha512::hash(key), cipherdata.data(), cipherdata.size());
        return { result.data(), result.size() };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_encrypt_file(const std::string& path, const std::string& key, const std::string& add)
{
    try
    {
        aes_encryption_stream stream { key, add };

        auto modification_rule = [&stream](const std::string& input_chunk, size_t current_byte) -> std::string {
            std::string result;
            if (!current_byte)
                result = stream.start();

            result.append(stream.encrypt(input_chunk));
            return result;
        };

        auto result = impl::modify_binary_inplace(path, 10 * 1024, modification_rule, 0);
        SSL_HELPERS_ASSERT(result.second = result.first + add.size());

        return stream.finalize();
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}

void aes_decrypt_file(const std::string& path, const std::string& key, const std::string& tag, const std::string& add)
{
    try
    {
        aes_decryption_stream stream { key, add };

        auto modification_rule = [&stream](const std::string& input_chunk, size_t current_byte) -> std::string {
            if (!current_byte)
                stream.start();

            return stream.decrypt(input_chunk);
        };

        auto result = impl::modify_binary_inplace(path, 10 * 1024, modification_rule, add.size());
        SSL_HELPERS_ASSERT(result.second = result.first - add.size());

        stream.finalize(tag);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}

} // namespace ssl_helpers
