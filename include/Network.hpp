#pragma once

#include <string>
#include <array>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#endif

class Socket
{
public:
    Socket();
    ~Socket();

    void create();
    void bind(int port);
    void listen();
    SOCKET acceptClient();

    void connect(const std::string& ip, int port);

    void send(const std::string& data);
    int sendBytes(const char* data, int size);
    int sendBytesDebug(const char* data, int size);

    int sendNonce(const std::array<uint8_t, 16>& nonce);

    std::string recv();
    int recvBytes(char* buffer, int size);

    int recvBytesDebug(char* buffer, int size);

    std::array<uint8_t, 16> recvNonce();

    void setHandle(SOCKET s);

private:
    SOCKET sock;
};