#include <iostream>
#include "Crypto.hpp"
#include "Config.hpp"
#include "Utils.hpp"

int main()
{
    std::cout << "Crypto test running\n";

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