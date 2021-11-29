#ifndef _SSL_HELPERS_DEFINES_
#define _SSL_HELPERS_DEFINES_

#include "platform_config.h"

#include <stdexcept>

// Workaround for varying preprocessing behavior between MSVC and gcc.
#define SSL_HELPERS_EXPAND_MACRO(x) x

// Suppress warning "conditional expression is constant" in the while(0) for visual c++
// http://cnicholson.net/2009/03/stupid-c-tricks-dowhile0-and-c4127/
#define SSL_HELPERS_MULTILINE_MACRO_BEGIN \
    do                                    \
    {
#ifdef _MSC_VER
#define SSL_HELPERS_MULTILINE_MACRO_END   \
    __pragma(warning(push))               \
        __pragma(warning(disable : 4127)) \
    }                                     \
    while (0)                             \
    __pragma(warning(pop))
#else
#define SSL_HELPERS_MULTILINE_MACRO_END \
    }                                   \
    while (0)
#endif

#define SSL_HELPERS_THROW_EXCEPTION(EXCEPTION, ...) \
    SSL_HELPERS_MULTILINE_MACRO_BEGIN               \
    throw EXCEPTION(__VA_ARGS__);                   \
    SSL_HELPERS_MULTILINE_MACRO_END

#define SSL_HELPERS_ASSERT(TEST, ...)                                      \
    SSL_HELPERS_EXPAND_MACRO(                                              \
        SSL_HELPERS_MULTILINE_MACRO_BEGIN if (!(TEST)) {                   \
            std::string s_what { #TEST ": " };                             \
            s_what += std::string { __VA_ARGS__ };                         \
            SSL_HELPERS_THROW_EXCEPTION(std::logic_error, s_what.c_str()); \
        } SSL_HELPERS_MULTILINE_MACRO_END)

#define SSL_HELPERS_ERROR(...) \
    SSL_HELPERS_ASSERT(false, __VA_ARGS__)

#endif //_SSL_HELPERS_DEFINES_
