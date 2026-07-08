#include "Network.hpp"
#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <string>
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"
#include "Crypto.hpp"
#include "Config.hpp"
#pragma comment(lib, "ws2_32.lib")

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    Socket server;
    server.create();
    server.bind(54000);
    server.listen();

    std::cout << "Server Listening..." << "\n";

    SOCKET clientSock = server.acceptClient();

    std::cout << "Connection with Client established" << "\n";

    Socket client;
    client.setHandle(clientSock);

    uint64_t filesize = 0;
    uint64_t nameLen = 0;
    
    client.recvBytes((char*)&filesize, sizeof(filesize));
    client.recvBytes((char*)&nameLen, sizeof(nameLen));

    std::string filename;
    filename.resize(nameLen);
    client.recvBytes(&filename[0], nameLen);

    std::string receivedHash;
    receivedHash.resize(64);
    client.recvBytes(&receivedHash[0], 64);

    std::string folderPath = "../../received/";
    std::string destinationPath = folderPath + filename;

    std::ofstream out(destinationPath, std::ios::binary);

    std::cout << "Filename: " << filename << ". Received hash: " << receivedHash << "\n";

    std::cout << "Receiving encrypted chunked file data..." <<"\n";

    char buffer[BUFFER_SIZE];
    AES256CTR aes(AES_KEY, AES_IV);

    uint64_t remaining = filesize;

    std::cout << "Remaining to receive: " << remaining << "\n";

    while (remaining > 0)
    {
        uint32_t chunkSize = 0;

        int r1 = client.recvBytes((char*)&chunkSize, sizeof(chunkSize));

        if (r1 <= 0) break;

        std::cout << "Receiving chunk. Size: " << chunkSize << "\n";

        std::vector<uint8_t> encrypted(chunkSize);

        int r2 = client.recvBytes((char*)encrypted.data(), chunkSize);
        if (r2 <= 0) break;

        std::cout << "Encrypted chunk: " << toHex(encrypted) << "\n";

        std::vector<uint8_t> decrypted = aes.process(encrypted);

        out.write((char*)decrypted.data(), decrypted.size());

        std::cout << "Decrypted chunk: " << decrypted.data() << "\n";

        remaining -= decrypted.size();
        std::cout << "Remaining to receive: " << remaining << "\n";
    }

    // Acknowledgement
    char ack = 1;
    client.sendBytes(&ack, sizeof(ack));

    out.close();

    std::cout << "Finished writing to file\n";

    std::cout << "Performing integrity check\n";

    auto computedHash = hashToString(SHA256Bcrypt::hashFile(destinationPath));

    std::cout << "Hash computed by server: " << computedHash << "\n";

    if (receivedHash == computedHash)
        std::cout << "Integrity: passed\n";
    else
        std::cout << "File is corrupted\n";

    WSACleanup();
}