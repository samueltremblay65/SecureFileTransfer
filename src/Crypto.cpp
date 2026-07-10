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

ECDHKeyPair::ECDHKeyPair()
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &algorithmHandle,
        BCRYPT_ECDH_P256_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to open ECDH provider");


    status = BCryptGenerateKeyPair(
        algorithmHandle,
        &privateKey,
        256,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(
            algorithmHandle,
            0);

        throw std::runtime_error("Failed to generate ECDH key pair");
    }


    status = BCryptFinalizeKeyPair(
        privateKey,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(privateKey);
        BCryptCloseAlgorithmProvider(
            algorithmHandle,
            0);

        throw std::runtime_error("Failed to finalize ECDH key pair");
    }
}


ECDHKeyPair::~ECDHKeyPair()
{
    if (privateKey != nullptr)
    {
        BCryptDestroyKey(privateKey);
    }

    if (algorithmHandle != nullptr)
    {
        BCryptCloseAlgorithmProvider(
            algorithmHandle,
            0);
    }
}

std::vector<uint8_t> ECDHKeyPair::getPublicKey() const
{
    NTSTATUS status;

    ULONG keyBlobSize = 0;

    status = BCryptExportKey(
        privateKey,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        nullptr,
        0,
        &keyBlobSize,
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to determine public key size");


    std::vector<uint8_t> publicKey(keyBlobSize);


    status = BCryptExportKey(
        privateKey,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        publicKey.data(),
        keyBlobSize,
        &keyBlobSize,
        0);

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to export public key");


    return publicKey;
}

std::vector<uint8_t> ECDHKeyPair::deriveSharedSecret(const std::vector<uint8_t>& peerPublicKey) const
{
    NTSTATUS status;

    BCRYPT_KEY_HANDLE peerKey = nullptr;

    status = BCryptImportKeyPair(
        algorithmHandle,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &peerKey,
        const_cast<PUCHAR>(peerPublicKey.data()),
        peerPublicKey.size(),
        0
    );

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to import peer public key");


    BCRYPT_SECRET_HANDLE secretHandle = nullptr;

    status = BCryptSecretAgreement(
        privateKey,
        peerKey,
        &secretHandle,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(peerKey);
        throw std::runtime_error("Failed to create shared secret");
    }


    ULONG secretSize = 0;

    status = BCryptDeriveKey(
        secretHandle,
        BCRYPT_KDF_RAW_SECRET,
        nullptr,
        nullptr,
        0,
        &secretSize,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroySecret(secretHandle);
        BCryptDestroyKey(peerKey);
        throw std::runtime_error("Failed to get secret size");
    }


    std::vector<uint8_t> secret(secretSize);


    status = BCryptDeriveKey(
        secretHandle,
        BCRYPT_KDF_RAW_SECRET,
        nullptr,
        secret.data(),
        secret.size(),
        &secretSize,
        0
    );

    BCryptDestroySecret(secretHandle);
    BCryptDestroyKey(peerKey);


    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to derive shared secret");


    return secret;
}

std::array<uint8_t, 32> deriveAESKey(const std::vector<uint8_t>& sharedSecret)
{
    BCRYPT_ALG_HANDLE shaAlg = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &shaAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to open SHA256 provider");


    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    status = BCryptCreateHash(
        shaAlg,
        &hashHandle,
        nullptr,
        0,
        nullptr,
        0,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(shaAlg, 0);
        throw std::runtime_error("Failed to create hash");
    }


    status = BCryptHashData(
        hashHandle,
        const_cast<PUCHAR>(sharedSecret.data()),
        sharedSecret.size(),
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(shaAlg, 0);
        throw std::runtime_error("Failed to hash shared secret");
    }


    std::array<uint8_t, 32> aesKey{};


    status = BCryptFinishHash(
        hashHandle,
        aesKey.data(),
        aesKey.size(),
        0
    );


    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(shaAlg, 0);


    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("Failed to finalize SHA256");


    return aesKey;
}