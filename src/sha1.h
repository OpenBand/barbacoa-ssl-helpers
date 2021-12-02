#pragma once

#include <string>

#include <openssl/sha.h>


namespace ssl_helpers {
namespace impl {

    class sha1
    {
    public:
        sha1();
        explicit sha1(const std::string& hex_str);

        std::string str() const;
        operator std::string() const;

        char* data() const;
        size_t data_size() const { return 160 / 8; }

        static sha1 hash(const char* d, uint32_t dlen);
        static sha1 hash(const std::string&);

        template <typename T>
        static sha1 hash(const T& t)
        {
            sha1::encoder e;
            e << t;
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
            sha1 result();

        private:
            SHA_CTX _context;
        };

        template <typename T>
        inline friend T& operator<<(T& ds, const sha1& ep)
        {
            ds.write(ep.data(), sizeof(ep));
            return ds;
        }

        template <typename T>
        inline friend T& operator>>(T& ds, sha1& ep)
        {
            ds.read(ep.data(), sizeof(ep));
            return ds;
        }
        friend sha1 operator<<(const sha1& h1, uint32_t i);
        friend bool operator==(const sha1& h1, const sha1& h2);
        friend bool operator!=(const sha1& h1, const sha1& h2);
        friend sha1 operator^(const sha1& h1, const sha1& h2);
        friend bool operator>=(const sha1& h1, const sha1& h2);
        friend bool operator>(const sha1& h1, const sha1& h2);
        friend bool operator<(const sha1& h1, const sha1& h2);

        uint32_t _hash[160 / 32];
    };

} // namespace impl
} // namespace ssl_helpers
