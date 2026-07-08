#include <iostream>
#include "Crypto.hpp"
#include "Config.hpp"
#include "Utils.hpp"

int main()
{
    std::cout << "Crypto test running\n";

    auto nonce = AES256CTR::generateNonce();
    AES256CTR aes(AES_KEY, nonce);

    std::vector<uint8_t> data = {'H','e','l','l','o'};

    auto encrypted = aes.process(data);

    std::cout << toHex(encrypted) << "\n";
    std::cout << encrypted.data() << "\n";

    auto decrypted = aes.process(encrypted);

    std::string result(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted: " << result << "\n";

    return 0;
}