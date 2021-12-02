#include <memory>
#include <mutex>
#include <thread>

#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifndef OPENSSL_THREADS
#error "OpenSSL must be configured to support threads"
#endif

#include "openssl_crypto_api.h"


namespace ssl_helpers {
namespace impl {

    struct openssl_scope
    {
        struct openssl_thread_config
        {
            static std::mutex* popenssl_mutexes;
            static unsigned long get_thread_id();
            static void locking_callback(int mode, int type, const char* file, int line);

            openssl_thread_config();
            ~openssl_thread_config();
        };
        std::unique_ptr<openssl_thread_config> _popenssl_thread_config_manager;

        openssl_scope()
        {
            // Initialize Libcrypto API (https://wiki.openssl.org/index.php/Libcrypto_API)

            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            OPENSSL_config(nullptr);
#endif //for OpenSSL < 1.1

            // For Thread Safety

            _popenssl_thread_config_manager = std::make_unique<openssl_thread_config>();
        }

        ~openssl_scope()
        {
            _popenssl_thread_config_manager.reset();
            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            ERR_free_strings();
        }
    };

    // Warning: It doesn't install own handlers if another library has
    //          installed them before us which is a partial solution,
    //          but you'd really need to evaluate each library
    //          that does this to make sure they will play nice.
    openssl_scope::openssl_thread_config::openssl_thread_config()
    {
        if (CRYPTO_get_id_callback() == NULL && CRYPTO_get_locking_callback() == NULL)
        {
            popenssl_mutexes = new std::mutex[CRYPTO_num_locks()];
            CRYPTO_set_id_callback(&get_thread_id);
            CRYPTO_set_locking_callback(&locking_callback);
        }
    }

    openssl_scope::openssl_thread_config::~openssl_thread_config()
    {
        if (CRYPTO_get_id_callback() == &get_thread_id)
        {
            CRYPTO_set_id_callback(NULL);
            CRYPTO_set_locking_callback(NULL);
            delete[] popenssl_mutexes;
            popenssl_mutexes = nullptr;
        }
    }

    std::mutex* openssl_scope::openssl_thread_config::popenssl_mutexes = nullptr;

    unsigned long openssl_scope::openssl_thread_config::get_thread_id()
    {
        return static_cast<unsigned long>(std::hash<std::thread::id> {}(std::this_thread::get_id()));
    }

    void openssl_scope::openssl_thread_config::locking_callback(int mode, int type, const char* file, int line)
    {
        if (mode & CRYPTO_LOCK)
            popenssl_mutexes[type].lock();
        else
            popenssl_mutexes[type].unlock();
    }

    // Initialize:
    //      Libcrypto API - YES
    //      Libssl API - NO (!)
    //
    // Warning: This function is not thread-safe itself!
    //          Call before any thread creation.
    //
    void init_openssl_crypto_api()
    {
        static std::unique_ptr<openssl_scope> ossl;

        ossl.release();
        ossl.reset(new openssl_scope());
    }

} // namespace impl
} // namespace ssl_helpers
