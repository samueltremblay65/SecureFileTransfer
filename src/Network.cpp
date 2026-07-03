#include "Network.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

Socket::Socket() : sock(INVALID_SOCKET) {}

Socket::~Socket()
{
    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
}

void Socket::create()
{
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("socket failed");
}

void Socket::bind(int port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("bind failed");
}

void Socket::listen()
{
    if (::listen(sock, 1) < 0)
        throw std::runtime_error("listen failed");
}

SOCKET Socket::acceptClient()
{
    return (SOCKET)::accept(sock, nullptr, nullptr);
}

void Socket::connect(const std::string& ip, int port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (::connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("connect failed");
}

void Socket::send(const std::string& data)
{
    ::send(sock, data.c_str(), (int)data.size(), 0);
}

int Socket::sendBytes(const char* data, int size)
{
    int total = 0;

    while (total < size)
    {
        int sent = ::send(sock, data + total, size - total, 0);
        std::cout << "Bytes sent: " << sent << "\n";

        if (sent <= 0)
            return sent;

        total += sent;
    }

    return total;
}

std::string Socket::recv()
{
    char buffer[4096];
    int bytes = ::recv(sock, buffer, sizeof(buffer), 0);

    if (bytes <= 0)
        return "";

    return std::string(buffer, bytes);
}

int Socket::recvBytes(char* buffer, int size)
{
    int total = 0;

    while (total < size)
    {
        int bytes = ::recv(sock, buffer + total, size - total, 0);

        std::cout << "Bytes received: " << bytes << "\n";

        if (bytes <= 0)
            return bytes;

        total += bytes;
    }

    return total;
}

void Socket::setHandle(SOCKET s)
{
    sock = s;
}