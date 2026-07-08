#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include "Crypto.hpp"
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"
#include "Config.hpp"

#pragma comment(lib, "ws2_32.lib")

#include "Network.hpp"

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    Socket client;
    client.create();
    client.connect("127.0.0.1", 54000);

    std::array<uint8_t, 16Ui64> nonce = AES256CTR::generateNonce();
    AES256CTR aes(AES_KEY, nonce);

    client.sendNonce(nonce);

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

    // Sending file metadata including integrity hash
    client.sendBytes((char*)&filesize, sizeof(filesize));
    client.sendBytes((char*)&nameLen, sizeof(nameLen));
    client.sendBytes(filename.c_str(), nameLen);
    client.sendBytes((char*)hash.c_str(), 64);

    std::cout << "filesize:" << filesize << "\n";
    std::cout << "nameLen:" << nameLen << "\n";

    std::cout << filename.c_str() << ": hash -> " << hash.c_str() << "\n" << std::flush;

    // Now send file data through a buffer
    char buffer[BUFFER_SIZE];

    // file.gcount returns how many bytes were read by the previous read
    // This ensures all bytes get sent, not just full chunks
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        int bytesRead = (int)file.gcount();

        std::vector<uint8_t> plain(buffer, buffer + bytesRead);
        std::vector<uint8_t> encrypted = aes.process(plain);

        uint32_t size = (uint32_t)encrypted.size();
        client.sendBytes((char*)&size, sizeof(size));

        std::cout << "Encrypted Chunk Size: " << size << "\n";
        client.sendBytes((char*)encrypted.data(), size);
    }

    file.close();

    // Wait for server acknowledgement before closing socket connection
    char ack = 0;
    client.recvBytes(&ack, sizeof(ack));

    WSACleanup();
}