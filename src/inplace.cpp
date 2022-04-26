#include <vector>

#include "ssl_helpers_defines.h"
#include "inplace.h"


namespace ssl_helpers {
namespace impl {

    file_context::file_context(const std::string& path)
    {
        SSL_HELPERS_ASSERT(path.size() > 0, "File required");

        namespace bf = boost::filesystem;

        _path = path;

        SSL_HELPERS_ASSERT(bf::exists(_path) && bf::is_regular_file(_path), "File required");

        _sz = bf::file_size(_path);

        SSL_HELPERS_ASSERT(_sz > 0, "Empty file");

        _pf = std::make_unique<std::fstream>(path, std::fstream::binary | std::fstream::in | std::fstream::out);

        SSL_HELPERS_ASSERT(valid(true));
    }

    file_context::operator bool() const
    {
        return valid(true);
    }

    void file_context::resize(size_t new_sz)
    {
        boost::filesystem::resize_file(_path, new_sz);
    }

    std::fstream& file_context::stream()
    {
        SSL_HELPERS_ASSERT(valid(false), "Invalid file");
        return *_pf;
    }

    bool file_context::valid(bool check_state) const
    {
        if (!_sz || !_pf)
            return false;
        return !check_state || _pf->good();
    }

    modify_binary_result_type modify_binary_inplace(file_context& file,
                                                    size_t chunk_sz,
                                                    modification_rule_type modification_rule,
                                                    const std::string& header)
    {
        try
        {
            SSL_HELPERS_ASSERT(chunk_sz > 0);

            SSL_HELPERS_ASSERT(file, "Invalid file");
            SSL_HELPERS_ASSERT(!file.stream().tellg(), "Zero start position expected");

            const size_t total_input_sz = file.size();
            size_t input_sz = total_input_sz;
            size_t total_output_sz = 0;

            auto read_wrapper = [&](size_t sz) -> std::string {
                SSL_HELPERS_ASSERT(input_sz > 0);
                SSL_HELPERS_ASSERT(!file.stream().bad(), strerror(errno));

                std::vector<char> vchunk;
                vchunk.resize(sz);
                file.stream().read(vchunk.data(), sz);
                vchunk.resize(file.stream().gcount());

                std::string chunk { vchunk.data(), vchunk.size() };

                input_sz -= chunk.size();
                return chunk;
            };
            auto write_wrapper = [&](const std::string& data) {
                if (data.size() > 0)
                {
                    file.stream().write(data.data(), data.size());
                    SSL_HELPERS_ASSERT(!file.stream().bad(), strerror(errno));
                    total_output_sz += data.size();
                }
            };
            auto write_to_available_space = [write_wrapper](const size_t pos_r, const size_t pos_w, const std::string& data) -> std::string {
                auto sz = data.size();
                auto left = pos_r - pos_w;
                if (left >= sz)
                    write_wrapper(data);
                else
                {
                    write_wrapper(data.substr(0, left));
                    return data.substr(left);
                }
                return {};
            };

            size_t pos_r = 0;
            if (!header.empty())
            {
                auto actual_header = read_wrapper(header.size());

                SSL_HELPERS_ASSERT(actual_header == header && file && input_sz > 0, "Invalid file format");

                pos_r = file.stream().tellg();
            }
            size_t pos_w = 0;

            std::string rest;

            while (input_sz > 0)
            {
                file.stream().seekg(pos_r);
                auto input_chunk = read_wrapper(chunk_sz);

                if (!file.stream().eof())
                {
                    pos_r = file.stream().tellg();
                }
                else
                {
                    pos_r = total_input_sz;
                    // Restore stream state if previous read reached EOF
                    file.stream().clear();
                }
                file.stream().seekg(pos_w);

                if (!rest.empty())
                {
                    rest = write_to_available_space(pos_r, pos_w, rest);
                    pos_w = file.stream().tellg();
                }

                auto output_chunk = modification_rule(input_chunk, !input_sz);
                SSL_HELPERS_ASSERT(!output_chunk.empty(), "Lost data");

                rest.append(write_to_available_space(pos_r, pos_w, output_chunk));
                pos_w = file.stream().tellg();
            }

            if (!rest.empty())
            {
                file.stream().seekg(total_output_sz);
                write_wrapper(rest);
            }
            else if (input_sz != total_output_sz)
            {
                file.resize(total_output_sz);
            }

            return std::make_pair(total_input_sz, total_output_sz);
        }
        catch (std::exception& e)
        {
            SSL_HELPERS_ASSERT(false, e.what());
        }

        return std::make_pair(0, 0);
    }

} // namespace impl
} // namespace ssl_helpers
