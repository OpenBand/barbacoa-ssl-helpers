project( BarbacoaSSLhelpers )
cmake_minimum_required( VERSION 2.8.12 )

set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL QUIET)

if (OpenSSL_FOUND)

    message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

    include_directories(${OPENSSL_INCLUDE_DIR})

else()
    message(FATAL_ERROR "OpenSSL lib required")

endif()

set(SSL_HELPERS_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ripemd160.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sha256.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sha512.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sha1.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/md5.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/base58.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/base64.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hash.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/random.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/encoding.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/convert_helper.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp"
)
file(GLOB_RECURSE SSL_HELPERS_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")

add_library( ssl-helpers
             ${SSL_HELPERS_SOURCES}
             ${SSL_HELPERS_HEADERS} )
target_link_libraries( ssl-helpers
                    ${OPENSSL_LIBRARIES}
                    ${PLATFORM_SPECIFIC_LIBS})
target_include_directories( ssl-helpers
                      PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )

option(SSL_HELPERS_TEST_PLATFORM_ANDROID "Forcibly set PLATFORM = ANDROID to test compiling (ON OR OFF)" OFF)
option(SSL_HELPERS_TEST_PLATFORM_IOS "Forcibly set PLATFORM = IOS to test compiling (ON OR OFF)" OFF)
option(SSL_HELPERS_TEST_PLATFORM_WINDOWS "Forcibly set PLATFORM = WINDOWS to test compiling (ON OR OFF)" OFF)

if (SSL_HELPERS_TEST_PLATFORM_ANDROID)
  target_compile_definitions( ssl-helpers PRIVATE -DTEST_PLATFORM_ANDROID)
else()
  if (SSL_HELPERS_TEST_PLATFORM_IOS)
      target_compile_definitions( ssl-helpers PRIVATE -DTEST_PLATFORM_IOS)
  else()
      if (SSL_HELPERS_TEST_PLATFORM_WINDOWS)
          target_compile_definitions( ssl-helpers PRIVATE -DTEST_PLATFORM_WINDOWS)
      endif()
  endif()
endif()

option(SSL_HELPERS_BUILD_TESTS "Build SSL-helpers tests (ON OR OFF). This option makes sense only for integrated library!" OFF)

# If this lib is not a sub-project:
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    set(SSL_HELPERS_BUILD_TESTS ON)
endif()

if (SSL_HELPERS_BUILD_TESTS)

    if ( NOT BOOST_VERSION_MIN )
        set(BOOST_VERSION_MIN "1.58")
    endif()

    set(BOOST_COMPONENTS)
    list(APPEND BOOST_COMPONENTS system
                                 filesystem
                                 unit_test_framework)
    set( Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF" )
    set( Boost_USE_MULTITHREADED ON CACHE STRING "ON or OFF" )

    find_package(Boost ${BOOST_VERSION_MIN} REQUIRED COMPONENTS ${BOOST_COMPONENTS})

    if(NOT Boost_FOUND)
        message(ERROR "Boost required for tests!")
    else()
        include_directories( ${Boost_INCLUDE_DIR} )

        file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
        file(GLOB TEST_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h")
        add_executable( ssl_helpers_tests ${TEST_SOURCES} ${TEST_HEADERS})
        add_dependencies( ssl_helpers_tests
                          ssl-helpers)
        target_link_libraries( ssl_helpers_tests
                               ssl-helpers
                               ${PLATFORM_SPECIFIC_LIBS}
                               ${Boost_LIBRARIES})
    endif()
endif()
