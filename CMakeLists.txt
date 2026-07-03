cmake_minimum_required(VERSION 3.20)

project(SecureFileTransfer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(client
    src/Client.cpp
    src/Crypto.cpp
    src/Network.cpp
    src/FileTransfer.cpp
    src/Utils.cpp
    src/sha256_bcrypt.cpp
)

target_include_directories(client PRIVATE include)

add_executable(server
    src/Server.cpp
    src/Crypto.cpp
    src/Network.cpp
    src/FileTransfer.cpp
    src/Utils.cpp
    src/sha256_bcrypt.cpp
)

target_include_directories(server PRIVATE include)