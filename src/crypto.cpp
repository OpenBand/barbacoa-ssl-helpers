#include <sstream>

#include <openssl/rand.h>

#include <ssl_helpers/crypto.h>
#include <ssl_helpers/hash.h>
#include <ssl_helpers/random.h>

#include "crypto_stream_impl.h"
#include "sha256.h"
#include "inplace.h"


namespace ssl_helpers {

std::string aes_to_string(const aes_256bit_type& data)
{
    return impl::to_string(data);
}

aes_256bit_type aes_from_string(const std::string& tag)
{
    return impl::create_from_string<aes_256bit_type>(tag.data(), tag.size());
}

aes_encryption_stream::aes_encryption_stream(const context& ctx,
                                             const std::string& default_key,
                                             const std::string& default_add)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        _impl = std::make_unique<impl::__aes_encryption_stream>(ctx, default_key, default_add);
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

aes_tag_type aes_encryption_stream::finalize()
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

aes_decryption_stream::aes_decryption_stream(const context& ctx,
                                             const std::string& default_key,
                                             const std::string& default_add)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        _impl = std::make_unique<impl::__aes_decryption_stream>(ctx, default_key, default_add);
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

void aes_decryption_stream::finalize(const aes_tag_type& tag)
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

void aes_decryption_stream::finalize()
{
    try
    {
        _impl->finalize({ 0 });
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}

salted_key_type aes_create_salted_key(const context& ctx, const std::string& key)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        SSL_HELPERS_ASSERT(!key.empty(), "Key required");

        aes_salt_type salt;
        SSL_HELPERS_ASSERT(1 == RAND_bytes((unsigned char*)salt.data(), salt.size()), "Can't get random data for salt");

        std::string salt_str { salt.data(), salt.size() };
        return { create_pbkdf2_512(key, salt_str), salt };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_get_salted_key(const std::string& key, const std::string& salt)
{
    try
    {
        SSL_HELPERS_ASSERT(!key.empty(), "Key required");
        SSL_HELPERS_ASSERT(!salt.empty(), "Salt required");

        return create_pbkdf2_512(key, salt);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_get_salted_key(const std::string& key, const aes_salt_type& salt)
{
    return aes_get_salted_key(key, std::string { salt.data(), salt.size() });
}

std::string aes_encrypt(const context& ctx,
                        const std::string& plain_data, const std::string& key)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

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

std::string aes_encrypt(const context& ctx,
                        const std::string& plain_data, const std::string& key,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag,
                        std::string& created_check_tag)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        impl::aes_block cipher;
        std::string result_str;
        {
            std::vector<char> result = cipher.encrypt(impl::sha512::hash(key), plain_data.data(), plain_data.size());
            result_str = { result.data(), result.size() };
        }
        created_check_tag = create_check_tag(key, result_str);
        return result_str;
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_decrypt(const context& ctx,
                        const std::string& cipher_data, const std::string& key)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        impl::aes_block cipher;
        std::vector<char> result = cipher.decrypt(impl::sha512::hash(key), cipher_data.data(), cipher_data.size());
        return { result.data(), result.size() };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_decrypt(const context& ctx,
                        const std::string& cipher_data, const std::string& key,
                        const std::string& check_tag,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        impl::aes_block cipher;
        auto input_check_tag = create_check_tag(key, cipher_data);
        if (check_tag != input_check_tag)
            return {};

        std::vector<char> result = cipher.decrypt(impl::sha512::hash(key), cipher_data.data(), cipher_data.size());
        return { result.data(), result.size() };
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }

    return {};
}

std::string aes_encrypt_file(const context& ctx,
                             const std::string& path,
                             const std::string& key,
                             const std::string& add,
                             bool save_tag_to_file)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        aes_encryption_stream stream { ctx, key, add };
        bool started = false;
        std::string tag;

        auto modification_rule = [&stream, &started, &tag, save_tag_to_file](
                                     const std::string& input_chunk, bool final) -> std::string {
            std::string result;
            if (!started)
            {
                started = true;
                result = stream.start();
            }

            result.append(stream.encrypt(input_chunk));
            if (final)
            {
                tag = aes_to_string(stream.finalize());
                if (save_tag_to_file)
                    result.append(tag);
            }
            return result;
        };

        impl::file_context f(path);
        auto result = impl::modify_binary_inplace(f, ctx().file_buffer_size(), modification_rule, {});
        SSL_HELPERS_ASSERT(result.second = result.first + add.size());

        return tag;
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}

void aes_decrypt_file(const context& ctx,
                      const std::string& path,
                      const std::string& key,
                      const std::string& add,
                      const std::string& tag,
                      bool read_tag_from_file)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        constexpr auto AES_TAG_SZ = aes_tag_type {}.size();

        aes_decryption_stream stream { ctx, key, add };
        bool started = false;

        auto modification_rule = [&stream, &started, tag, read_tag_from_file](
                                     const std::string& input_chunk, bool final) -> std::string {
            if (!started)
            {
                started = true;
                stream.start();
            }

            if (final)
            {
                std::string result;
                std::string tag_;
                if (read_tag_from_file)
                {
                    auto to_tag = input_chunk.size() - AES_TAG_SZ;
                    result = stream.decrypt(input_chunk.substr(0, to_tag));
                    tag_ = input_chunk.substr(to_tag);
                }
                else
                {
                    result = stream.decrypt(input_chunk);
                }

                if (!tag.empty())
                {
                    SSL_HELPERS_ASSERT(tag_.empty() || tag == tag_, "Inconsistent tags");
                    stream.finalize(aes_from_string(tag));
                }
                else
                {
                    if (!tag_.empty())
                    {
                        stream.finalize(aes_from_string(tag_));
                    }
                    else
                    {
                        stream.finalize();
                    }
                }

                return result;
            }
            else
            {
                return stream.decrypt(input_chunk);
            }
        };

        impl::file_context f(path);

        auto chunk_sz = ctx().file_buffer_size();
        if (read_tag_from_file)
        {
            auto data_sz = f.size() - add.size();

            SSL_HELPERS_ASSERT(data_sz > AES_TAG_SZ, "Invalid file");

            while (data_sz % chunk_sz < AES_TAG_SZ)
            {
                chunk_sz += 1;
            }
        }

        auto result = impl::modify_binary_inplace(f, chunk_sz, modification_rule, add);
        SSL_HELPERS_ASSERT(result.second = result.first - add.size());
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
}

flip_session_type aes_ecnrypt_flip(const context& ctx,
                                   const std::string& plain_data,
                                   const std::string& instant_key,
                                   const std::string& marker,
                                   bool add_garbage)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        std::string session_data;

        auto salted_key = aes_create_salted_key(ctx, instant_key);

        std::string cipher_data;
        aes_tag_type tag;

        {
            aes_encryption_stream stream(ctx);

            std::ostringstream out;

            out << stream.start(salted_key.first, marker);
            out << stream.encrypt(plain_data);
            tag = stream.finalize();

            cipher_data = out.str();
        }

        {
            std::ostringstream out;

            out << marker;
            const auto& salt = salted_key.second;
            out.write(salt.data(), salt.size());
            out.write(tag.data(), tag.size());

            if (add_garbage)
            {
                aes_salt_type garbage;

                auto garbage_len = create_random(ctx) % garbage.size() + 1;
                if (garbage_len > garbage.size())
                    garbage_len = garbage.size();

                SSL_HELPERS_ASSERT(1 == RAND_bytes((unsigned char*)garbage.data(), garbage.size()), "Can't get random data for garbage");

                out.write(garbage.data(), garbage_len);
            }

            session_data = out.str();
        }

        return std::make_pair(cipher_data, session_data);
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}

std::string aes_decrypt_flip(const context& ctx,
                             const flip_session_type& session_data,
                             const std::string& instant_key,
                             const std::string& marker)
{
    return aes_decrypt_flip(ctx, session_data.first, session_data.second, instant_key, marker);
}

std::string aes_decrypt_flip(const context& ctx,
                             const std::string& cipher_data,
                             const std::string& session_data,
                             const std::string& user_key,
                             const std::string& marker)
{
    try
    {
        SSL_HELPERS_ASSERT(ctx().is_enabled_libcrypto_api(), "Libcrypto API required");

        aes_salt_type salt;
        aes_tag_type tag;

        {
            std::istringstream in(session_data);

            if (!marker.empty())
            {
                std::vector<char> marker_buff(marker.size());
                in.read(marker_buff.data(), marker_buff.size());
                SSL_HELPERS_ASSERT(!in.fail(), "Insufficient data");

                SSL_HELPERS_ASSERT(std::string(marker_buff.data(), marker_buff.size()) == marker, "Invalid marker");
            }

            in.read(salt.data(), salt.size());
            SSL_HELPERS_ASSERT(!in.fail(), "Insufficient data");

            in.read(tag.data(), tag.size());
            SSL_HELPERS_ASSERT(!in.fail(), "Insufficient data");
        }

        std::ostringstream out;
        {
            std::istringstream in(cipher_data);

            if (!marker.empty())
            {
                std::vector<char> marker_buff(marker.size());
                in.read(marker_buff.data(), marker_buff.size());
                SSL_HELPERS_ASSERT(!in.fail(), "Insufficient data");

                SSL_HELPERS_ASSERT(std::string(marker_buff.data(), marker_buff.size()) == marker, "Invalid marker");
            }

            aes_decryption_stream stream(ctx);

            stream.start(aes_get_salted_key(user_key, salt), marker);

            char buff[1024];

            for (std::streamsize bytes_read = 1; in.read(buff, sizeof(buff)) || bytes_read > 0;)
            {
                bytes_read = in.gcount();
                if (bytes_read > 0)
                {
                    std::string cipher_payload { buff, static_cast<uint32_t>(bytes_read) };
                    out << stream.decrypt(cipher_payload);
                }
            }

            stream.finalize(tag);
        }

        return out.str();
    }
    catch (std::exception& e)
    {
        SSL_HELPERS_ASSERT(false, e.what());
    }
    return {};
}

} // namespace ssl_helpers
