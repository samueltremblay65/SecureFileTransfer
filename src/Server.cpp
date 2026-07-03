#include "Network.hpp"
#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <string>
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"
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
    uint64_t hashLen = 0;

    std::cout << "Receiving..." <<"\n";
    
    client.recvBytes((char*)&filesize, sizeof(filesize));
    client.recvBytes((char*)&nameLen, sizeof(nameLen));
    client.recvBytes((char*)&hashLen, sizeof(hashLen));

    std::string filename;
    filename.resize(nameLen);
    client.recvBytes(&filename[0], nameLen);

    std::string receivedHash;
    receivedHash.resize(hashLen);
    client.recvBytes(&receivedHash[0], hashLen);


    std::string folderPath = "../../received/";
    std::string destinationPath = folderPath + filename;

    std::ofstream out(destinationPath, std::ios::binary);

    char buffer[4096];

    // Bytes remaining to be sent
    uint64_t remaining = filesize;

    while (remaining > 0)
    {
        int toRead = (remaining < sizeof(buffer)) ? (int)remaining : sizeof(buffer);

        int bytes = client.recvBytes(buffer, toRead);
        if (bytes <= 0) break;

        out.write(buffer, bytes);
        remaining -= bytes;
    }

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