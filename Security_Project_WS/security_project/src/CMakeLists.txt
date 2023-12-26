cmake_minimum_required(VERSION 3.10)
project(YourProjectName)

# Set the path to OpenSSL root folder
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Check if OpenSSL was found
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Set OPENSSL_ROOT_DIR to the root installation directory of OpenSSL.")
endif()

# Set source files
set(SOURCES
    main.cpp
    rsa.cpp
    aes.cpp
)

# Add the executable
add_executable(main ${SOURCES})

# Include OpenSSL headers
target_include_directories(main PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link against OpenSSL libraries
target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_custom_target(run
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/main
    DEPENDS main
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running main project"
)