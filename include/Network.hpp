#pragma once

#include <string>

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

    std::string recv();
    int recvBytes(char* buffer, int size);

    void setHandle(SOCKET s);

private:
    SOCKET sock;
};