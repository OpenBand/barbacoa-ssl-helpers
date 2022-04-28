#pragma once

#include <string>

#include <openssl/sha.h>


namespace ssl_helpers {
namespace impl {

    class sha256
    {
    public:
        sha256();
        explicit sha256(const std::string& hex_str);
        explicit sha256(const char* data, size_t size);

        std::string str() const;

        char* data() const;
        size_t data_size() const { return 256 / 8; }

        static sha256 hash(const char* d, uint32_t dlen);
        static sha256 hash(const std::string&);
        static sha256 hash(const sha256&);

        template <typename T>
        static sha256 hash(const T& t)
        {
            sha256::encoder e;
            pack(e, t);
            return e.result();
        }

        class encoder
        {
        public:
            encoder();
            ~encoder();

            void write(const char* d, uint32_t dlen);
            void put(char c) { write(&c, 1); }
            void reset();
            sha256 result();

        private:
            SHA256_CTX _context;
        };

        template <typename T>
        inline friend T& operator<<(T& ds, const sha256& ep)
        {
            ds.write(ep.data(), sizeof(ep));
            return ds;
        }

        template <typename T>
        inline friend T& operator>>(T& ds, sha256& ep)
        {
            ds.read(ep.data(), sizeof(ep));
            return ds;
        }
        friend sha256 operator<<(const sha256& h1, uint32_t i);
        friend sha256 operator>>(const sha256& h1, uint32_t i);
        friend bool operator==(const sha256& h1, const sha256& h2);
        friend bool operator!=(const sha256& h1, const sha256& h2);
        friend sha256 operator^(const sha256& h1, const sha256& h2);
        friend bool operator>=(const sha256& h1, const sha256& h2);
        friend bool operator>(const sha256& h1, const sha256& h2);
        friend bool operator<(const sha256& h1, const sha256& h2);

        uint64_t _hash[256 / 64];
    };

} // namespace impl
} // namespace ssl_helpers
