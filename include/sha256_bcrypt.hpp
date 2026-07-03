#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

class SHA256Bcrypt
{
public:
    static std::vector<unsigned char> hashFile(const std::string& path);
};