#pragma once

#include <string>

#include <openssl/md5.h>


namespace ssl_helpers {
namespace impl {

    class md5
    {
    public:
        md5();
        explicit md5(const std::string& hex_str);

        std::string str() const;
        operator std::string() const;

        char* data() const;
        size_t data_size() const { return 128 / 8; }

        static md5 hash(const char* d, uint32_t dlen);
        static md5 hash(const std::string&);

        template <typename T>
        static md5 hash(const T& t)
        {
            md5::encoder e;
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
            md5 result();

        private:
            MD5_CTX _context;
        };

        template <typename T>
        inline friend T& operator<<(T& ds, const md5& ep)
        {
            ds.write(ep.data(), sizeof(ep));
            return ds;
        }

        template <typename T>
        inline friend T& operator>>(T& ds, md5& ep)
        {
            ds.read(ep.data(), sizeof(ep));
            return ds;
        }
        friend md5 operator<<(const md5& h1, uint32_t i);
        friend bool operator==(const md5& h1, const md5& h2);
        friend bool operator!=(const md5& h1, const md5& h2);
        friend md5 operator^(const md5& h1, const md5& h2);
        friend bool operator>=(const md5& h1, const md5& h2);
        friend bool operator>(const md5& h1, const md5& h2);
        friend bool operator<(const md5& h1, const md5& h2);

        uint32_t _hash[128 / 32];
    };

} // namespace impl
} // namespace ssl_helpers
