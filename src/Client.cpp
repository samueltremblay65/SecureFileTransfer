#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"

#pragma comment(lib, "ws2_32.lib")

#include "Network.hpp"

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    Socket client;
    client.create();
    client.connect("127.0.0.1", 54000);

    std::string filename = "sample.txt";
    std::string sampleFolderPath = "../../sample/";
    std::string filepath = sampleFolderPath + filename;

    std::ifstream file(filepath, std::ios::binary);

    // Return pointer to start so we can read the file
    file.seekg(0, std::ios::beg);

    // Move pointer to the end of the file
    file.seekg(0, std::ios::end);
    // Measure file size
    uint64_t filesize = file.tellg();
    // Put pointer back at the beginning to read
    file.seekg(0, std::ios::beg);

    uint64_t nameLen = filename.size();

    // Performing integrity hashing
    std::string hash = hashToString(SHA256Bcrypt::hashFile(filepath));
    std::cout << "Hash sent to server: " << hash << "\n";

    // Sending file metadata including integrity hash
    client.sendBytes((char*)&filesize, sizeof(filesize));
    client.sendBytes((char*)&nameLen, sizeof(nameLen));
    client.sendBytes(filename.c_str(), nameLen);
    client.sendBytes((char*)hash.c_str(), 64);

    std::cout << "filesize:" << filesize << "\n";
    std::cout << "nameLen:" << nameLen << "\n";

    std::cout << filename.c_str() << ": hash -> " << hash.c_str() << "\n";

    // Now send file data through a buffer
    char buffer[4096];

    // file.gcount returns how many bytes were read by the previous read
    // This ensures all bytes get sent, not just full chunks
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        client.sendBytes(buffer, (int)file.gcount());
    }

    file.close();
    WSACleanup();
}