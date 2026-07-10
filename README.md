# SecureFileTransfer

A secure file transfer application written in C++ using TCP sockets and Windows Cryptography API (BCrypt).

The goal of this project was to build a file transfer system from the ground up while learning how secure communication protocols are designed. Instead of relying on an existing protocol like FTP over TLS, this project implements a custom application protocol with its own handshake, key exchange, encryption, and integrity verification.

## Features

- TCP client/server file transfer
- Custom binary communication protocol
- Chunk-based file transmission
- AES-256 encryption for transferred data
- Ephemeral ECDH key exchange using Windows BCrypt
- Session key derivation from the shared secret
- SHA-256 file integrity verification
- Transfer acknowledgement system

