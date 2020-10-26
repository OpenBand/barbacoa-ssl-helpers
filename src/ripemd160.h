#pragma once

#include <openssl/ripemd.h>

#include <string>

namespace ssl_helpers {
namespace impl {
    class sha512;
    class sha256;

    class ripemd160
    {
    public:
        ripemd160();
        explicit ripemd160(const std::string& hex_str);

        std::string str() const;
        explicit operator std::string() const;

        char* data() const;
        size_t data_size() const { return 160 / 8; }

        static ripemd160 hash(const sha512& h);
        static ripemd160 hash(const sha256& h);
        static ripemd160 hash(const char* d, uint32_t dlen);
        static ripemd160 hash(const std::string&);

        template <typename T>
        static ripemd160 hash(const T& t)
        {
            ripemd160::encoder e;
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
            ripemd160 result();

        private:
            RIPEMD160_CTX _context;
        };

        template <typename T>
        inline friend T& operator<<(T& ds, const ripemd160& ep)
        {
            ds.write(ep.data(), sizeof(ep));
            return ds;
        }

        template <typename T>
        inline friend T& operator>>(T& ds, ripemd160& ep)
        {
            ds.read(ep.data(), sizeof(ep));
            return ds;
        }
        friend ripemd160 operator<<(const ripemd160& h1, uint32_t i);
        friend bool operator==(const ripemd160& h1, const ripemd160& h2);
        friend bool operator!=(const ripemd160& h1, const ripemd160& h2);
        friend ripemd160 operator^(const ripemd160& h1, const ripemd160& h2);
        friend bool operator>=(const ripemd160& h1, const ripemd160& h2);
        friend bool operator>(const ripemd160& h1, const ripemd160& h2);
        friend bool operator<(const ripemd160& h1, const ripemd160& h2);

        uint32_t _hash[5];
    };

} // namespace impl
} // namespace ssl_helpers
