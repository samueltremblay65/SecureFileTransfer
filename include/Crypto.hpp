#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>
#pragma comment(lib, "bcrypt.lib")

std::array<uint8_t, 32> deriveAESKey(const std::vector<uint8_t>& sharedSecret);

class AES256CTR
{
public:

    AES256CTR(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 16>& nonce);

    ~AES256CTR();

    std::vector<uint8_t> process(
        const std::vector<uint8_t>& input);

    static std::array<uint8_t,16> generateNonce();

private:

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE keyHandle = nullptr;

    std::vector<uint8_t> keyObject;

    std::array<uint8_t, 16> nonce;

    std::int32_t counter = 0;
};

class ECDHKeyPair
{
public:

    ECDHKeyPair();

    ~ECDHKeyPair();

    std::vector<uint8_t> getPublicKey() const;

    std::vector<uint8_t> deriveSharedSecret(
        const std::vector<uint8_t>& peerPublicKey
    ) const;

private:

    BCRYPT_ALG_HANDLE algorithmHandle = nullptr;

    BCRYPT_KEY_HANDLE privateKey = nullptr;
};


std::array<uint8_t, 32> hkdfSha256(
    const std::vector<uint8_t>& sharedSecret
);