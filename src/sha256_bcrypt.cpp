#include "sha256_bcrypt.hpp"

std::vector<unsigned char> SHA256Bcrypt::hashFile(const std::string& path)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );

    if (status < 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    DWORD objLen = 0;
    DWORD data = 0;

    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&objLen,
        sizeof(objLen),
        &data,
        0
    );

    std::vector<BYTE> hashObject(objLen);

    status = BCryptCreateHash(
        hAlg,
        &hHash,
        hashObject.data(),
        objLen,
        nullptr,
        0,
        0
    );

    if (status < 0)
        throw std::runtime_error("BCryptCreateHash failed");

    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Cannot open file");

    char buffer[4096];

    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        status = BCryptHashData(
            hHash,
            (PUCHAR)buffer,
            (ULONG)file.gcount(),
            0
        );

        if (status < 0)
            throw std::runtime_error("BCryptHashData failed");
    }

    std::vector<unsigned char> hash(32);
    status = BCryptFinishHash(
        hHash,
        hash.data(),
        32,
        0
    );

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status < 0)
        throw std::runtime_error("BCryptFinishHash failed");

    return hash;
}