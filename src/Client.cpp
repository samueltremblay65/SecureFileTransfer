#include "Network.hpp"
#include "Protocol.hpp"
#include "Crypto.hpp"
#include "sha256_bcrypt.hpp"
#include "Utils.hpp"
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

    Socket client;

    client.create();

    client.connect("127.0.0.1", 54000);

    sendHello(client);
    recvHelloAck(client);

    ECDHKeyPair keys;

    auto publicKey = keys.getPublicKey();

    sendKeyExchange(client, publicKey);

    auto serverPublicKey = recvKeyExchange(client);

    auto sharedSecret = keys.deriveSharedSecret(serverPublicKey);

    std::cout << "Shared secret size: " << sharedSecret.size() << "\n";

    std::array<uint8_t, NONCE_SIZE> nonce = AES256CTR::generateNonce();

    auto aesKey = deriveAESKey(sharedSecret);
    AES256CTR aes(aesKey, nonce);

    std::string filename = "sample.txt";
    std::string filepath = "../../sample/" + filename;

    std::ifstream file(filepath, std::ios::binary);
    file.seekg(0, std::ios::end);

    uint64_t filesize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string hash = hashToString(SHA256Bcrypt::hashFile(filepath));

    sendFileInfo(
        client,
        filesize,
        filename,
        hash,
        nonce
    );

    std::cout << "Filename: " << filename << "\n";

    char buffer[BUFFER_SIZE];

    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        int bytesRead = static_cast<int>(file.gcount());

        std::vector<uint8_t> plain(
            buffer,
            buffer + bytesRead
        );

        std::vector<uint8_t> encrypted =aes.process(plain);

        sendFileChunk(client, encrypted);

        std::cout << "Sent encrypted chunk: "<< encrypted.size() << " bytes\n";
    }

    file.close();

    sendTransferComplete(client);

    recvAck(client);

    std::cout << "Transfer complete\n";

    WSACleanup();
}