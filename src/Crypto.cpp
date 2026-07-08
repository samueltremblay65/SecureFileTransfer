#include <stdexcept>

#include "Crypto.hpp"

AES256CTR::AES256CTR(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 16>& nonce)
    : nonce(nonce)
{
    NTSTATUS status;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to open AES provider.");

    // Use ECB mode (CTR is implemented manually)
    status = BCryptSetProperty(
        algorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB),
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to set chaining mode.");

    // Determine required key object size
    DWORD keyObjectSize = 0;
    DWORD bytesReturned = 0;

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjectSize,
        sizeof(keyObjectSize),
        &bytesReturned,
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to query key object size.");

    keyObject.resize(keyObjectSize);

    // Create AES key
    status = BCryptGenerateSymmetricKey(
        algorithm,
        &keyHandle,
        keyObject.data(),
        keyObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to create AES key.");
}

AES256CTR::~AES256CTR() {};

std::vector<uint8_t> AES256CTR::process(const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output;
    output.reserve(input.size());

    size_t index = 0;

    while (index < input.size())
    {
        std::array<uint8_t, 16> counterBlock = nonce;

        // Overwriting the last 8 bytes with the current counter (big-endian)
        for (int i = 0; i < 8; i++)
        {
            counterBlock[15 - i] =
                static_cast<uint8_t>(counter >> (8 * i));
        }

        // Encrypting the counter block
        std::array<uint8_t, 16> keystream;

        DWORD bytesDone = 0;

        NTSTATUS status = BCryptEncrypt(
            keyHandle,
            counterBlock.data(),
            16,
            nullptr,
            nullptr,
            0,
            keystream.data(),
            16,
            &bytesDone,
            0);

        if (!BCRYPT_SUCCESS(status))
        {
            throw std::runtime_error("BCryptEncrypt failed.");
        }

        // XOR Step
        for (size_t i = 0; i < 16 && index < input.size(); i++, index++)
        {
            output.push_back(input[index] ^ keystream[i]);
        }

        // Next counter value
        counter++;
    }

    return output;
}

std::array<uint8_t, 16> AES256CTR::generateNonce()
{
    std::array<uint8_t, 16> nonce;

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        nonce.data(),
        static_cast<ULONG>(nonce.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status))
    {
        throw std::runtime_error("Failed to generate nonce.");
    }

    return nonce;
}