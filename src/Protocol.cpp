#include <iostream>

#include "Protocol.hpp"
#include "Network.hpp"

void sendPacketHeader(Socket& socket, PacketType type, uint32_t payloadSize)
{
    PacketHeader header;

    header.version = PROTOCOL_VERSION;
    header.type = type;
    header.payloadSize = payloadSize;

    socket.sendBytes(
        reinterpret_cast<char*>(&header),
        sizeof(header)
    );
}

PacketHeader recvPacketHeader(Socket& socket)
{
    PacketHeader header;

    socket.recvBytes(
        reinterpret_cast<char*>(&header),
        sizeof(header)
    );

    return header;
}

void sendFileInfo(
    Socket& socket,
    uint64_t fileSize,
    const std::string& filename,
    const std::string& hash,
    const std::array<uint8_t, NONCE_SIZE>& nonce)
{
    FileInfoHeader info;

    info.fileSize = fileSize;
    info.fileNameLength = filename.size();

    uint32_t payloadSize =
        sizeof(FileInfoHeader) +
        filename.size() +
        SHA256_HASH_SIZE +
        NONCE_SIZE;

    sendPacketHeader(
        socket,
        PacketType::FileInfo,
        payloadSize
    );

    socket.sendBytes(
        reinterpret_cast<char*>(&info),
        sizeof(info)
    );

    socket.sendBytes(
        filename.data(),
        filename.size()
    );

    socket.sendBytes(
        hash.data(),
        SHA256_HASH_SIZE
    );

    socket.sendBytes(
        reinterpret_cast<const char*>(nonce.data()),
        NONCE_SIZE
    );
}

void recvFileInfo(
    Socket& socket,
    uint64_t& fileSize,
    std::string& filename,
    std::string& hash,
    std::array<uint8_t, NONCE_SIZE>& nonce)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::FileInfo)
        throw std::runtime_error("Expected FileInfo packet");

    FileInfoHeader info;

    socket.recvBytes(
        reinterpret_cast<char*>(&info),
        sizeof(info)
    );

    fileSize = info.fileSize;

    filename.resize(info.fileNameLength);

    socket.recvBytes(
        filename.data(),
        filename.size()
    );

    hash.resize(SHA256_HASH_SIZE);

    socket.recvBytes(
        hash.data(),
        SHA256_HASH_SIZE
    );

    socket.recvBytes(
        reinterpret_cast<char*>(nonce.data()),
        NONCE_SIZE
    );
}


void sendFileChunk(
    Socket& socket,
    const std::vector<uint8_t>& encrypted)
{
    uint32_t chunkSize = encrypted.size();

    uint32_t payloadSize =
        sizeof(chunkSize) +
        chunkSize;

    sendPacketHeader(
        socket,
        PacketType::FileData,
        payloadSize
    );

    socket.sendBytes(
        reinterpret_cast<char*>(&chunkSize),
        sizeof(chunkSize)
    );

    socket.sendBytes(
        reinterpret_cast<const char*>(encrypted.data()),
        encrypted.size()
    );
}


std::vector<uint8_t> recvFileChunk(Socket& socket)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::FileData)
        throw std::runtime_error("Expected FileData packet");

    uint32_t chunkSize;

    socket.recvBytes(
        reinterpret_cast<char*>(&chunkSize),
        sizeof(chunkSize)
    );

    std::vector<uint8_t> encrypted(chunkSize);

    socket.recvBytes(
        reinterpret_cast<char*>(encrypted.data()),
        chunkSize
    );

    return encrypted;
}

void sendTransferComplete(Socket& socket)
{
    sendPacketHeader(
        socket,
        PacketType::TransferComplete,
        0
    );
}

void sendAck(Socket& socket)
{
    char ack = 1;

    sendPacketHeader(
        socket,
        PacketType::Ack,
        sizeof(ack)
    );

    socket.sendBytes(
        &ack,
        sizeof(ack)
    );
}

void recvAck(Socket& socket)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::Ack)
        throw std::runtime_error("Expected ACK");

    char ack;

    socket.recvBytes(
        &ack,
        sizeof(ack)
    );

    if (ack != 1)
        throw std::runtime_error("Transfer failed");
}

void recvHello(Socket& socket)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::Hello)
        throw std::runtime_error("Expected Hello");

    HelloPacket hello;

    socket.recvBytes(
        reinterpret_cast<char*>(&hello),
        sizeof(hello));

    if (hello.protocolVersion != PROTOCOL_VERSION)
        throw std::runtime_error("Unsupported protocol");
}

void sendHello(Socket& socket)
{
    HelloPacket hello;

    hello.protocolVersion = PROTOCOL_VERSION;

    sendPacketHeader(
        socket,
        PacketType::Hello,
        sizeof(HelloPacket));

    socket.sendBytes(
        reinterpret_cast<char*>(&hello),
        sizeof(hello));
}

void sendHelloAck(Socket& socket)
{
    sendPacketHeader(
        socket,
        PacketType::HelloAck,
        0);
}

void recvHelloAck(Socket& socket)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::HelloAck)
        throw std::runtime_error("Expected HelloAck");
}

void sendKeyExchange(Socket& socket, const std::vector<uint8_t>& publicKey)
{
    sendPacketHeader(
        socket,
        PacketType::KeyExchange,
        publicKey.size()
    );

    socket.sendBytes(
        reinterpret_cast<const char*>(publicKey.data()),
        publicKey.size()
    );
}

std::vector<uint8_t> recvKeyExchange(Socket& socket)
{
    PacketHeader header = recvPacketHeader(socket);

    if (header.type != PacketType::KeyExchange)
        throw std::runtime_error("Expected KeyExchange packet");

    std::vector<uint8_t> publicKey(
        header.payloadSize
    );

    socket.recvBytes(
        reinterpret_cast<char*>(publicKey.data()),
        publicKey.size()
    );

    return publicKey;
}