#include "Network.hpp"
#include "Protocol.hpp"
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"
#include "Crypto.hpp"
#include "Config.hpp"

#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    Socket server;

    server.create();
    server.bind(54000);
    server.listen();

    std::cout << "Server Listening...\n";

    SOCKET clientSock = server.acceptClient();

    std::cout << "Connection with Client established\n";

    Socket client;
    client.setHandle(clientSock);

    recvHello(client);
    sendHelloAck(client);

    ECDHKeyPair keys;

    auto clientPublicKey = recvKeyExchange(client);
    auto publicKey = keys.getPublicKey();

    sendKeyExchange(client, publicKey);

    auto sharedSecret = keys.deriveSharedSecret(clientPublicKey);

    std::cout << "Shared secret size: " << sharedSecret.size() << "\n";

    uint64_t filesize;
    std::string filename;
    std::string receivedHash;
    std::array<uint8_t, NONCE_SIZE> nonce;

    recvFileInfo(
        client,
        filesize,
        filename,
        receivedHash,
        nonce
    );

    auto aesKey = deriveAESKey(sharedSecret);
    AES256CTR aes(aesKey, nonce);

    std::string folderPath = "../../received/";
    std::string destinationPath = folderPath + filename;

    std::ofstream out(
        destinationPath,
        std::ios::binary
    );

    std::cout 
        << "Filename: "
        << filename
        << "\nReceived hash: "
        << receivedHash
        << "\n";

    std::cout << "Receiving file...\n";

    uint64_t receivedBytes = 0;

    while (true)
    {
        PacketHeader header = recvPacketHeader(client);

        if (header.type == PacketType::TransferComplete)
        {
            break;
        }

        if (header.type != PacketType::FileData)
        {
            std::cout << "Unexpected packet type\n";
            break;
        }

        uint32_t chunkSize;

        client.recvBytes(
            reinterpret_cast<char*>(&chunkSize),
            sizeof(chunkSize)
        );

        std::vector<uint8_t> encrypted(chunkSize);

        client.recvBytes(
            reinterpret_cast<char*>(encrypted.data()),
            chunkSize
        );

        std::vector<uint8_t> decrypted =
            aes.process(encrypted);

        out.write(
            reinterpret_cast<char*>(decrypted.data()),
            decrypted.size()
        );

        receivedBytes += decrypted.size();

        std::cout
            << "Received "
            << receivedBytes
            << " / "
            << filesize
            << " bytes\n";
    }


    out.close();


    std::cout << "Finished writing file\n";


    std::cout << "Performing integrity check\n";


    std::string computedHash =
        hashToString(
            SHA256Bcrypt::hashFile(destinationPath)
        );


    if (receivedHash == computedHash)
    {
        std::cout << "Integrity: passed\n";
    }
    else
    {
        std::cout << "File is corrupted\n";
    }


    sendAck(client);


    WSACleanup();
}