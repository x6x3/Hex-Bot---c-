cmake_minimum_required(VERSION 3.15)
project(HexBot)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

if(WIN32)
    find_package(Boost REQUIRED COMPONENTS system)
else()
    find_package(Boost REQUIRED COMPONENTS system)
endif()

add_executable(hex-bot Hex-bot.c++)

target_include_directories(hex-bot PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    /opt/homebrew/include
    /opt/homebrew/opt/openssl/include
    /opt/homebrew/opt/boost/include
    /opt/homebrew/opt/nlohmann-json/include
)

if(WIN32)
    target_link_libraries(hex-bot 
        PRIVATE 
        CURL::libcurl
        OpenSSL::SSL 
        OpenSSL::Crypto
        Boost::system
        ws2_32
        wldap32
        winmm
        crypt32
    )
    
    set_target_properties(hex-bot PROPERTIES
        WIN32_EXECUTABLE TRUE
        OUTPUT_NAME "hex-bot"
    )
else()
    target_link_libraries(hex-bot 
        PRIVATE 
        CURL::libcurl
        OpenSSL::SSL 
        OpenSSL::Crypto
        Boost::system
        pthread
    )
endif()

if(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
    target_link_libraries(hex-bot PRIVATE ${CORE_FOUNDATION} ${SECURITY_FRAMEWORK})
endif()

set(CMAKE_BUILD_TYPE Release)

if(MSVC)
    target_compile_options(hex-bot PRIVATE /W4)
else()
    target_compile_options(hex-bot PRIVATE -Wall -Wextra -O3)
endif()