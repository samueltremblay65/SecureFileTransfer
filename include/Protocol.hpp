#pragma once

#include <cstdint>
#include <vector>
#include <string>

class Socket;

constexpr uint16_t PROTOCOL_VERSION = 1;
constexpr uint32_t SHA256_HASH_SIZE = 64;
constexpr uint32_t NONCE_SIZE = 16;

enum class PacketType : uint16_t
{
    Hello = 1,
    FileInfo,
    FileData,
    TransferComplete,
    Ack,
    Error
};

#pragma pack(push, 1)

struct PacketHeader
{
    uint16_t version;
    PacketType type;
    uint32_t payloadSize;
};

struct FileInfoHeader
{
    uint64_t fileSize;
    uint64_t fileNameLength;
};

#pragma pack(pop)

void sendPacketHeader(Socket& socket, PacketType type, uint32_t payloadSize);

PacketHeader recvPacketHeader(Socket& socket);

void sendFileInfo(
    Socket& socket,
    uint64_t fileSize,
    const std::string& filename,
    const std::string& hash,
    const std::array<uint8_t, NONCE_SIZE>& nonce
);

void recvFileInfo(
    Socket& socket,
    uint64_t& fileSize,
    std::string& filename,
    std::string& hash,
    std::array<uint8_t, NONCE_SIZE>& nonce
);

void sendFileChunk(
    Socket& socket,
    const std::vector<uint8_t>& encrypted
);

std::vector<uint8_t> recvFileChunk(
    Socket& socket
);

void sendTransferComplete(Socket& socket);

void sendAck(Socket& socket);

void recvAck(Socket& socket);