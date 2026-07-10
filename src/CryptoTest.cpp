#include <iostream>
#include "Crypto.hpp"
#include "Config.hpp"
#include "Utils.hpp"

int main()
{
    std::cout << "Crypto test running\n";

    constexpr std::array<uint8_t, 32> AES_KEY =
    {
        0x10, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78,
        0x90, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF,
        0x01, 0x02, 0x03, 0x04
    };
    
    std::array<uint8_t, 16Ui64> nonce = AES256CTR::generateNonce();
    AES256CTR aes(AES_KEY, nonce);

    std::vector<uint8_t> data = {'H','e','l','l','o'};

    std::vector<unsigned char> encrypted = aes.process(data);

    std::cout << toHex(encrypted) << "\n";
    std::cout << encrypted.data() << "\n";

    std::vector<unsigned char> decrypted = aes.process(encrypted);

    std::string result(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted: " << result << "\n";

    return 0;
}