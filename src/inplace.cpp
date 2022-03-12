#include <fstream>
#include <vector>

#include "ssl_helpers_defines.h"
#include "inplace.h"


namespace ssl_helpers {
namespace impl {

    modify_binary_result_type modify_binary_inplace(const std::string& path,
                                                    size_t chunk_sz,
                                                    modification_rule_type modification_rule,
                                                    size_t pass_header_bytes)
    {

        try
        {
            SSL_HELPERS_ASSERT(chunk_sz > 0);

            namespace bf = boost::filesystem;

            bf::path path_ { path };

            SSL_HELPERS_ASSERT(bf::exists(path_) && bf::is_regular_file(path_), "File path required");

            size_t total_input_sz = bf::file_size(path_);
            size_t total_result_sz = 0;

            std::fstream f(path, std::fstream::binary | std::fstream::in | std::fstream::out);

            std::string rest;

            auto write_wrapper = [&f, &total_result_sz](const char* data, size_t sz) {
                if (sz > 0)
                {
                    f.write(data, sz);
                    SSL_HELPERS_ASSERT(!f.bad(), strerror(errno));
                    total_result_sz += sz;
                }
            };

            size_t pos_r = (pass_header_bytes > 0) ? pass_header_bytes : 0;
            size_t pos_w = 0;

            while (pos_r < total_input_sz)
            {
                f.seekg(pos_r);
                std::vector<char> vchunk;
                vchunk.resize(chunk_sz);
                f.read(vchunk.data(), chunk_sz);
                vchunk.resize(f.gcount());

                std::string chunk { vchunk.data(), vchunk.size() };

                // Free space for rest bytes
                size_t rest_sz = rest.size();
                while (!chunk.empty() && chunk.size() % chunk_sz == 0 && rest_sz >= chunk_sz)
                {
                    std::vector<char> vchunk_;
                    vchunk_.resize(chunk_sz);
                    f.read(vchunk_.data(), chunk_sz);
                    vchunk_.resize(f.gcount());

                    if (vchunk_.empty())
                        break;

                    chunk.append(vchunk_.data(), vchunk_.size());
                    rest_sz -= vchunk_.size();
                }

                if (!f.eof())
                {
                    pos_r = f.tellg();
                }
                else
                {
                    pos_r = total_input_sz;
                    // Restore stream state if previous read reached EOF
                    f.clear();
                }
                f.seekg(pos_w);

                // Write rest bytes
                if (!rest.empty())
                {
                    write_wrapper(rest.data(), rest.size());
                    rest.resize(0);
                    pos_w = f.tellg();
                }

                if (chunk.empty())
                    break;

                auto chunk_ = modification_rule(chunk, pos_w);
                SSL_HELPERS_ASSERT(!chunk_.empty(), "Empty modification");
                auto result_sz = chunk_.size();
                auto left = pos_r - pos_w;
                if (left >= result_sz)
                    write_wrapper(chunk_.data(), chunk_.size());
                else
                {
                    write_wrapper(chunk_.substr(0, left).data(), left);
                    rest = chunk_.substr(left);
                }
                pos_w = f.tellg();
            }

            if (!rest.empty())
            {
                f.clear();
                f.seekg(total_result_sz);
                write_wrapper(rest.data(), rest.size());
            }
            else if (total_input_sz != total_result_sz)
            {
                bf::resize_file(path_, total_result_sz);
            }
            f.close();

            return std::make_pair(total_input_sz, total_result_sz);
        }
        catch (std::exception& e)
        {
            SSL_HELPERS_ASSERT(false, e.what());
        }

        return std::make_pair(0, 0);
    }

} // namespace impl
} // namespace ssl_helpers
